/// Feature B — Quarantaine de fichier malveillant.
///
/// Protocole :
/// 1. Valide le chemin source
/// 2. Lit le fichier en bytes
/// 3. Chiffre avec AES-256-GCM (clé persistée dans le dossier quarantaine)
/// 4. Écrit le fichier chiffré dans %APPDATA%\FileScanner\quarantine\{sha256}.quar
///    Format : [12 bytes nonce][ciphertext + 16 bytes auth tag]
/// 5. Écrit les métadonnées dans %APPDATA%\FileScanner\quarantine\{sha256}.meta.json
/// 6. Supprime le fichier original
use std::path::{Path, PathBuf};
#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::ScanError;

const QUARANTINE_KEY_FILE: &str = "quarantine.key";

#[derive(Serialize, Deserialize)]
struct QuarantineMeta {
    original_path: String,
    sha256: String,
    quarantine_date: String,
    size_bytes: u64,
    encryption: String,
}

/// Répertoire de quarantaine : %APPDATA%\FileScanner\quarantine\
fn quarantine_dir() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("FileScanner")
        .join("quarantine")
}

/// Charge ou génère la clé AES-256 persistée sur disque.
///
/// Sécurité : la clé est stockée dans %APPDATA%\FileScanner\quarantine\quarantine.key.
/// Après création, on restreint les permissions via icacls pour que seul l'utilisateur
/// courant puisse lire le fichier (évite la lecture par d'autres processus locaux).
/// Note : pour un niveau de sécurité supérieur, envisager DPAPI (Windows CryptProtectData).
fn get_or_create_key(qdir: &Path) -> Result<[u8; 32], String> {
    let key_path = qdir.join(QUARANTINE_KEY_FILE);
    if key_path.exists() {
        let bytes = std::fs::read(&key_path).map_err(|e| e.to_string())?;
        if bytes.len() < 32 {
            return Err("Fichier clé corrompu (< 32 bytes)".to_string());
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes[..32]);
        Ok(key)
    } else {
        let key = Aes256Gcm::generate_key(OsRng);
        // Créée d'emblée en 0600 sous Unix (pas de fenêtre en 0644)
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        opts.open(&key_path)
            .and_then(|mut f| std::io::Write::write_all(&mut f, key.as_slice()))
            .map_err(|e| e.to_string())?;

        // Restreindre l'accès : seul l'utilisateur courant (pas Everyone, pas les autres users)
        // icacls <path> /inheritance:r /grant:r %USERNAME%:(R) — sans input utilisateur (safe)
        #[cfg(target_os = "windows")]
        {
            if let Ok(username) = std::env::var("USERNAME") {
                let key_str = key_path.to_string_lossy().to_string();
                // Désactiver l'héritage et ne garder que le propriétaire en lecture
                let _ = std::process::Command::new("icacls")
                    .args([
                        &key_str,
                        "/inheritance:r",
                        "/grant:r",
                        &format!("{}:(R)", username),
                    ])
                    .creation_flags(0x08000000) // CREATE_NO_WINDOW
                    .output();
            }
        }

        Ok(key.into())
    }
}

/// Chiffre `data` avec AES-256-GCM. Retourne [nonce (12 B)] + [ciphertext + tag].
fn encrypt_quarantine(data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, data)
        .map_err(|e| format!("AES-GCM encrypt error: {e:?}"))?;
    let mut result = nonce.to_vec(); // 12 bytes
    result.extend_from_slice(&ciphertext); // ciphertext + 16 bytes GCM tag
    Ok(result)
}

/// Déchiffre [nonce (12 B)] + [ciphertext + tag].
fn decrypt_quarantine(data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, String> {
    if data.len() < 12 + 16 {
        return Err("Fichier de quarantaine tronqué".to_string());
    }
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let (nonce, ct) = data.split_at(12);
    cipher
        .decrypt(aes_gcm::Nonce::from_slice(nonce), ct)
        .map_err(|_| "Déchiffrement impossible (clé ou fichier altéré)".to_string())
}

/// Écrit `data` dans un fichier qui ne doit PAS déjà exister.
fn write_new(path: &Path, data: &[u8]) -> Result<(), String> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .and_then(|mut f| std::io::Write::write_all(&mut f, data))
        .map_err(|e| format!("{} : {e}", path.display()))
}

/// Valide le chemin source (réutilise la même logique que commands.rs).
fn validate_source(raw: &str) -> Result<PathBuf, ScanError> {
    if crate::commands::has_parent_dir_segment(raw) {
        return Err(ScanError::Internal(
            "Chemin invalide : séquence '..' interdite".to_string(),
        ));
    }
    let canonical = Path::new(raw)
        .canonicalize()
        .map_err(|_| ScanError::AccessDenied("Chemin inaccessible".to_string()))?;
    if !canonical.is_file() {
        return Err(ScanError::Internal(
            "La cible n'est pas un fichier ordinaire".to_string(),
        ));
    }
    Ok(canonical)
}

/// Met `source` en quarantaine dans `qdir`. Le SHA-256 est calculé ici, jamais fourni par le client.
fn quarantine_into(qdir: &Path, source: &Path) -> Result<PathBuf, String> {
    std::fs::create_dir_all(qdir).map_err(|e| e.to_string())?;
    let key = get_or_create_key(qdir)?;

    let raw = std::fs::read(source).map_err(|e| e.to_string())?;
    let sha256 = hex::encode(Sha256::digest(&raw));
    let quar_path = qdir.join(format!("{sha256}.quar"));
    let meta_path = qdir.join(format!("{sha256}.meta.json"));
    if quar_path.exists() || meta_path.exists() {
        return Err("Un fichier identique est déjà en quarantaine".to_string());
    }

    let encrypted = encrypt_quarantine(&raw, &key)?;
    write_new(&quar_path, &encrypted)?;

    let meta = QuarantineMeta {
        original_path: source.display().to_string(),
        sha256: sha256.clone(),
        quarantine_date: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        size_bytes: raw.len() as u64,
        encryption: "AES-256-GCM".to_string(),
    };
    let meta_json = serde_json::to_string_pretty(&meta).map_err(|e| e.to_string())?;
    if let Err(e) = write_new(&meta_path, meta_json.as_bytes()) {
        let _ = std::fs::remove_file(&quar_path);
        return Err(e);
    }

    // Supprimer l'original seulement une fois la copie chiffrée écrite
    std::fs::remove_file(source).map_err(|e| e.to_string())?;
    Ok(quar_path)
}

/// Restaure le fichier `sha256` depuis `qdir` vers son chemin d'origine (jamais d'écrasement).
fn restore_from(qdir: &Path, sha256: &str) -> Result<PathBuf, String> {
    let sha256 = sha256.to_ascii_lowercase();
    if sha256.len() != 64 || !sha256.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("sha256 invalide".to_string());
    }
    let quar_path = qdir.join(format!("{sha256}.quar"));
    let meta_path = qdir.join(format!("{sha256}.meta.json"));
    let meta_raw = std::fs::read(&meta_path)
        .map_err(|_| "Aucun fichier en quarantaine pour ce hash".to_string())?;
    let meta: QuarantineMeta =
        serde_json::from_slice(&meta_raw).map_err(|e| format!("Métadonnées corrompues : {e}"))?;
    let key = get_or_create_key(qdir)?;
    let plain = decrypt_quarantine(&std::fs::read(&quar_path).map_err(|e| e.to_string())?, &key)?;
    if hex::encode(Sha256::digest(&plain)) != sha256 {
        return Err("Contenu restauré différent du hash d'origine".to_string());
    }
    let dest = PathBuf::from(&meta.original_path);
    write_new(&dest, &plain)?;
    let _ = std::fs::remove_file(&quar_path);
    let _ = std::fs::remove_file(&meta_path);
    Ok(dest)
}

#[tauri::command]
pub async fn quarantine_file(file_path: String) -> Result<String, String> {
    let source = validate_source(&file_path).map_err(|e| e.to_string())?;
    let quar_path = quarantine_into(&quarantine_dir(), &source)?;
    log::info!(
        "Fichier mis en quarantaine (AES-256-GCM) : {} → {}",
        source.display(),
        quar_path.display()
    );
    Ok(quar_path.display().to_string())
}

#[tauri::command]
pub async fn restore_quarantined(sha256: String) -> Result<String, String> {
    let dest = restore_from(&quarantine_dir(), &sha256)?;
    log::info!("Fichier restauré depuis la quarantaine : {}", dest.display());
    Ok(dest.display().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("fs_quar_{name}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn quarantine_uses_real_hash_refuses_duplicate_and_restores() {
        let base = tmp("roundtrip");
        let qdir = base.join("q");
        let src = base.join("evil.exe");
        std::fs::write(&src, b"MZ payload").unwrap();

        let quar = quarantine_into(&qdir, &src).unwrap();
        let real = hex::encode(Sha256::digest(b"MZ payload"));
        assert_eq!(quar.file_name().unwrap().to_string_lossy(), format!("{real}.quar"));
        assert!(!src.exists());

        // Même contenu une 2e fois : refus, et l'original n'est pas supprimé
        std::fs::write(&src, b"MZ payload").unwrap();
        assert!(quarantine_into(&qdir, &src).is_err());
        assert!(src.exists());
        std::fs::remove_file(&src).unwrap();

        let back = restore_from(&qdir, &real.to_uppercase()).unwrap();
        assert_eq!(std::fs::read(&back).unwrap(), b"MZ payload");
        assert!(!quar.exists());
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn restore_never_overwrites() {
        let base = tmp("nooverwrite");
        let qdir = base.join("q");
        let src = base.join("f.bin");
        std::fs::write(&src, b"abc").unwrap();
        quarantine_into(&qdir, &src).unwrap();
        std::fs::write(&src, b"new").unwrap();
        assert!(restore_from(&qdir, &hex::encode(Sha256::digest(b"abc"))).is_err());
        assert_eq!(std::fs::read(&src).unwrap(), b"new");
        std::fs::remove_dir_all(&base).ok();
    }

    #[cfg(unix)]
    #[test]
    fn key_is_0600() {
        use std::os::unix::fs::PermissionsExt;
        let base = tmp("key");
        get_or_create_key(&base).unwrap();
        let mode = std::fs::metadata(base.join(QUARANTINE_KEY_FILE)).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        std::fs::remove_dir_all(&base).ok();
    }
}
