//! Vérification de la signature d'un exécutable par Windows lui-même.
//!
//! 1. Signature Authenticode intégrée au fichier (WinVerifyTrust, WTD_CHOICE_FILE).
//! 2. Sinon, signature par CATALOGUE : la plupart des fichiers de Windows (notepad.exe…)
//!    n'embarquent aucune signature, leur empreinte figure dans un catalogue signé par
//!    Microsoft. L'empreinte ne dépend que du contenu : une copie hors de System32 est
//!    reconnue elle aussi.
//!
//! Hors Windows, seule la présence d'une signature intégrée est connue (non vérifiée).

use std::path::Path;

use crate::report::types::SignatureInfo;

#[cfg(not(windows))]
use crate::report::types::SigStatus;

#[cfg(not(windows))]
pub fn verify(_path: &Path, has_embedded: bool) -> SignatureInfo {
    SignatureInfo::new(if has_embedded { SigStatus::Unverified } else { SigStatus::Absent }, String::new())
}

#[cfg(windows)]
pub fn verify(path: &Path, has_embedded: bool) -> SignatureInfo {
    win::verify(path, has_embedded)
}

#[cfg(windows)]
mod win {
    use std::ffi::c_void;
    use std::fs::File;
    use std::os::windows::{ffi::OsStrExt, io::AsRawHandle};
    use std::path::Path;
    use std::ptr::{null, null_mut};

    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::Security::Cryptography::Catalog::{
        CryptCATAdminAcquireContext2, CryptCATAdminCalcHashFromFileHandle2, CryptCATAdminEnumCatalogFromHash,
        CryptCATAdminReleaseCatalogContext, CryptCATAdminReleaseContext, CryptCATCatalogInfoFromContext, CATALOG_INFO,
    };
    use windows_sys::Win32::Security::Cryptography::{CertGetNameStringW, CERT_NAME_SIMPLE_DISPLAY_TYPE};
    use windows_sys::Win32::Security::WinTrust::{
        WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData, WinVerifyTrust, DRIVER_ACTION_VERIFY,
        WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_CATALOG_INFO, WINTRUST_DATA, WINTRUST_FILE_INFO,
        WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_CATALOG, WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE,
        WTD_STATEACTION_VERIFY, WTD_UI_NONE,
    };

    use crate::report::types::{SigStatus, SignatureInfo};

    const fn hr(v: u32) -> i32 {
        v as i32
    }
    /// Aucune signature intégrée (ou format non signable).
    const NO_SIGNATURE: [i32; 3] = [hr(0x800B_0100), hr(0x800B_0003), hr(0x800B_0001)];
    /// Signature intacte (empreinte conforme) mais chaîne non reconnue : racine non installée,
    /// chaîne incomplète, certificat expiré sans horodatage, racine de test.
    const INTACT_UNTRUSTED: [i32; 4] = [hr(0x800B_0109), hr(0x800B_010A), hr(0x800B_0101), hr(0x800B_010D)];

    fn wide(s: &std::ffi::OsStr) -> Vec<u16> {
        s.encode_wide().chain(Some(0)).collect()
    }

    pub fn verify(path: &Path, has_embedded: bool) -> SignatureInfo {
        let Ok(file) = File::open(path) else {
            let st = if has_embedded { SigStatus::Unverified } else { SigStatus::Absent };
            return SignatureInfo::new(st, String::new());
        };
        let path_w = wide(path.as_os_str());

        let mut fi = WINTRUST_FILE_INFO { cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32, ..Default::default() };
        fi.pcwszFilePath = path_w.as_ptr();
        // SAFETY : fi et path_w vivent jusqu'à la fin de l'appel.
        let (code, signer) = unsafe { trust(WTD_CHOICE_FILE, &mut fi as *mut _ as *mut c_void) };
        if code == 0 {
            return SignatureInfo::new(SigStatus::Trusted, signer);
        }
        if INTACT_UNTRUSTED.contains(&code) {
            return SignatureInfo::new(SigStatus::Untrusted, signer);
        }
        if !NO_SIGNATURE.contains(&code) {
            return SignatureInfo::new(SigStatus::Invalid, format!("0x{:08X}", code as u32));
        }
        // SAFETY : file et path_w restent valides pendant toute la vérification.
        match unsafe { catalog(&file, &path_w) } {
            Some((0, signer)) => SignatureInfo::new(SigStatus::Catalog, signer),
            _ => SignatureInfo::new(SigStatus::Absent, String::new()),
        }
    }

    /// WinVerifyTrust avec état conservé (pour lire le signataire), puis libération.
    unsafe fn trust(choice: u32, data: *mut c_void) -> (i32, String) {
        let mut wd = WINTRUST_DATA {
            cbStruct: size_of::<WINTRUST_DATA>() as u32,
            dwUIChoice: WTD_UI_NONE,
            fdwRevocationChecks: WTD_REVOKE_NONE,
            dwUnionChoice: choice,
            dwStateAction: WTD_STATEACTION_VERIFY,
            // Jamais de réseau : la vérification reste locale et instantanée.
            dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL,
            ..Default::default()
        };
        if choice == WTD_CHOICE_FILE {
            wd.Anonymous.pFile = data.cast();
        } else {
            wd.Anonymous.pCatalog = data.cast();
        }
        let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        let code = WinVerifyTrust(null_mut(), &mut action, &mut wd as *mut _ as *mut c_void);
        let signer = signer_name(wd.hWVTStateData);
        wd.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(null_mut(), &mut action, &mut wd as *mut _ as *mut c_void);
        (code, signer)
    }

    /// Nom du certificat feuille du premier signataire (« Microsoft Windows », « Heiphaistos »).
    unsafe fn signer_name(state: HANDLE) -> String {
        if state.is_null() {
            return String::new();
        }
        let prov = WTHelperProvDataFromStateData(state);
        if prov.is_null() {
            return String::new();
        }
        let sgnr = WTHelperGetProvSignerFromChain(prov, 0, 0, 0);
        if sgnr.is_null() || (*sgnr).csCertChain == 0 || (*sgnr).pasCertChain.is_null() {
            return String::new();
        }
        let cert = (*(*sgnr).pasCertChain).pCert;
        if cert.is_null() {
            return String::new();
        }
        let mut buf = [0u16; 256];
        let n = CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, null(), buf.as_mut_ptr(), buf.len() as u32);
        String::from_utf16_lossy(&buf[..(n as usize).saturating_sub(1)])
    }

    /// Cherche l'empreinte du fichier dans les catalogues système et vérifie celui trouvé.
    // ponytail: catalogues SHA-256 seulement (tous ceux de Windows 10/11) ; ajouter un repli SHA-1 si un vieux pilote tiers doit être reconnu.
    unsafe fn catalog(file: &File, path_w: &[u16]) -> Option<(i32, String)> {
        let mut admin: isize = 0;
        if CryptCATAdminAcquireContext2(&mut admin, &DRIVER_ACTION_VERIFY, windows_sys::core::w!("SHA256"), null(), 0) == 0 {
            return None;
        }
        let h = file.as_raw_handle() as HANDLE;
        let mut len = 0u32;
        CryptCATAdminCalcHashFromFileHandle2(admin, h, &mut len, null_mut(), 0);
        let mut hash = vec![0u8; len as usize];
        let mut out = None;
        if len > 0 && CryptCATAdminCalcHashFromFileHandle2(admin, h, &mut len, hash.as_mut_ptr(), 0) != 0 {
            let cat = CryptCATAdminEnumCatalogFromHash(admin, hash.as_ptr(), len, 0, null_mut());
            if cat != 0 {
                let mut info = CATALOG_INFO { cbStruct: size_of::<CATALOG_INFO>() as u32, ..Default::default() };
                if CryptCATCatalogInfoFromContext(cat, &mut info, 0) != 0 {
                    let tag: Vec<u16> = hash.iter().map(|b| format!("{b:02X}")).collect::<String>().encode_utf16().chain(Some(0)).collect();
                    let mut ci = WINTRUST_CATALOG_INFO {
                        cbStruct: size_of::<WINTRUST_CATALOG_INFO>() as u32,
                        pcwszCatalogFilePath: info.wszCatalogFile.as_ptr(),
                        pcwszMemberTag: tag.as_ptr(),
                        pcwszMemberFilePath: path_w.as_ptr(),
                        hMemberFile: h,
                        pbCalculatedFileHash: hash.as_mut_ptr(),
                        cbCalculatedFileHash: len,
                        hCatAdmin: admin,
                        ..Default::default()
                    };
                    out = Some(trust(WTD_CHOICE_CATALOG, &mut ci as *mut _ as *mut c_void));
                }
                CryptCATAdminReleaseCatalogContext(admin, cat, 0);
            }
        }
        CryptCATAdminReleaseContext(admin, 0);
        out
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::verify;
    use crate::report::types::SigStatus;

    /// notepad.exe n'a aucune signature intégrée : Windows le signe par catalogue.
    /// Une copie hors de System32 garde la même empreinte, donc la même signature.
    #[test]
    fn copie_de_notepad_signee_par_catalogue() {
        let src = std::path::Path::new(r"C:\Windows\System32\notepad.exe");
        let dst = std::env::temp_dir().join(format!("fs_sig_{}_notepad.exe", std::process::id()));
        std::fs::copy(src, &dst).expect("copie de notepad");
        let s = verify(&dst, false);
        let _ = std::fs::remove_file(&dst);
        assert_eq!(s.status, SigStatus::Catalog, "{}", s.label);
        assert!(s.signer.contains("Microsoft"), "{}", s.signer);
    }

    #[test]
    fn fichier_sans_signature() {
        let dst = std::env::temp_dir().join(format!("fs_sig_{}_vide.exe", std::process::id()));
        std::fs::write(&dst, b"MZ pas un vrai programme").expect("écriture");
        let s = verify(&dst, false);
        let _ = std::fs::remove_file(&dst);
        assert_eq!(s.status, SigStatus::Absent, "{}", s.label);
    }
}
