use goblin::Object;
use std::path::Path;

use crate::analyzer::entropy::shannon_entropy;
use crate::error::ScanError;
use crate::report::types::{IoC, PeInfo, PeSection, Severity};

const SUSPICIOUS_IMPORTS: &[&str] = &[
    "VirtualAlloc",
    "VirtualAllocEx",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "NtUnmapViewOfSection",
    "ZwUnmapViewOfSection",
    "SetWindowsHookEx",
    "GetAsyncKeyState",
    "CryptEncrypt",
    "CryptDecrypt",
    "InternetOpen",
    "InternetConnect",
    "URLDownloadToFile",
    "ShellExecute",
    "WinExec",
    "CreateProcess",
    "OpenProcess",
    "ReadProcessMemory",
    "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess",
];

const PACKER_SIGNATURES: &[(&str, &[u8])] = &[
    ("UPX", b"UPX0"),
    ("UPX1", b"UPX1"),
    ("MPRESS", b"MPRESS1"),
    ("PECompact", b"PECompact2"),
    ("Themida", b"Themida"),
];

pub fn parse(path: &Path, raw_bytes: &[u8]) -> Result<(PeInfo, Vec<IoC>), ScanError> {
    let obj = Object::parse(raw_bytes)
        .map_err(|e| ScanError::PeParseError(e.to_string()))?;

    match obj {
        Object::PE(pe) => analyze_pe(path, raw_bytes, &pe),
        _ => Err(ScanError::PeParseError("Non-PE object".to_string())),
    }
}

fn analyze_pe(
    _path: &Path,
    raw_bytes: &[u8],
    pe: &goblin::pe::PE,
) -> Result<(PeInfo, Vec<IoC>), ScanError> {
    let is_64bit = pe.is_64;
    let entry_point = pe.entry as u64;

    let mut sections = Vec::new();
    let mut entropy_max: f64 = 0.0;

    for section in &pe.sections {
        let name = String::from_utf8_lossy(&section.name)
            .trim_matches('\0')
            .to_string();

        let start = section.pointer_to_raw_data as usize;
        let size = section.size_of_raw_data as usize;
        let end = (start + size).min(raw_bytes.len());

        let section_data = if start < raw_bytes.len() {
            &raw_bytes[start..end]
        } else {
            &[]
        };

        let entropy = shannon_entropy(section_data);
        if entropy > entropy_max {
            entropy_max = entropy;
        }

        sections.push(PeSection {
            name,
            virtual_size: section.virtual_size as u64,
            raw_size: section.size_of_raw_data as u64,
            entropy,
            characteristics: section.characteristics,
        });
    }

    let imports: Vec<String> = pe
        .imports
        .iter()
        .map(|i| i.name.to_string())
        .collect();

    let suspicious_imports: Vec<String> = imports
        .iter()
        .filter(|name| {
            SUSPICIOUS_IMPORTS
                .iter()
                .any(|s| name.to_lowercase().contains(&s.to_lowercase()))
        })
        .cloned()
        .collect();

    let is_packed = detect_packer(raw_bytes) || entropy_max > 7.2;
    let is_signed = detect_signature(pe);

    let mut ioc_list = Vec::new();

    if entropy_max > 7.2 {
        ioc_list.push(IoC {
            ioc_type: "Entropie".to_string(),
            value: format!("{:.2}", entropy_max),
            severity: if entropy_max > 7.5 {
                Severity::High
            } else {
                Severity::Medium
            },
            description: "Entropie élevée — possible packer ou chiffrement".to_string(),
        });
    }

    for import in &suspicious_imports {
        ioc_list.push(IoC {
            ioc_type: "Import suspect".to_string(),
            value: import.clone(),
            severity: classify_import_severity(import),
            description: format!("Fonction API critique : {}", import),
        });
    }

    if !is_signed {
        ioc_list.push(IoC {
            ioc_type: "Signature".to_string(),
            value: "Non signé".to_string(),
            severity: Severity::Low,
            description: "L'exécutable ne possède pas de signature numérique valide".to_string(),
        });
    }

    // Bug corrigé : utilise la signature binaire `sig` (2ème élément), pas le nom `name`
    // Avant : windows(4).any(w == name[..4]) → cherchait "Them", "MPRE" etc. = FP massifs
    // Après : windows(sig.len()).any(w == sig) → signature exacte
    for (name, sig) in PACKER_SIGNATURES {
        if raw_bytes
            .windows(sig.len())
            .any(|w| w == *sig)
        {
            ioc_list.push(IoC {
                ioc_type: "Packer".to_string(),
                value: name.to_string(),
                severity: Severity::Medium,
                description: format!("Signature du packer {} détectée", name),
            });
        }
    }

    Ok((
        PeInfo {
            is_64bit,
            is_signed,
            sections,
            imports,
            entry_point,
            entropy_max,
            suspicious_imports,
            is_packed,
        },
        ioc_list,
    ))
}

fn detect_packer(data: &[u8]) -> bool {
    PACKER_SIGNATURES
        .iter()
        .any(|(_, sig)| data.windows(sig.len()).any(|w| w == *sig))
}

const IMAGE_DIRECTORY_ENTRY_SECURITY: usize = 4;

fn detect_signature(pe: &goblin::pe::PE) -> bool {
    // goblin 0.9: data_directories est Vec<Option<(usize, DataDirectory)>>
    pe.header
        .optional_header
        .map(|oh| {
            oh.data_directories
                .data_directories
                .get(IMAGE_DIRECTORY_ENTRY_SECURITY)
                .and_then(|e| e.as_ref())
                .map(|(_, d)| d.virtual_address != 0)
                .unwrap_or(false)
        })
        .unwrap_or(false)
}

fn classify_import_severity(import: &str) -> Severity {
    // Critical : injection de processus — aucune app légitime n'a besoin de ça
    let critical = &[
        "CreateRemoteThread",
        "WriteProcessMemory",
        "NtUnmapViewOfSection",
        "ZwUnmapViewOfSection",
    ];
    // High : hooking, téléchargement, exécution directe — suspect mais pas forcément malveillant
    let high = &[
        "VirtualAllocEx",
        "SetWindowsHookEx",
        "URLDownloadToFile",
        "WinExec",
    ];
    // Medium : APIs réseau ou crypto — légitime dans certains contextes
    let medium = &[
        "CryptEncrypt",
        "CryptDecrypt",
        "InternetOpen",
        "InternetConnect",
        "ReadProcessMemory", // diagnostic tool : Medium (affiché, pas Critical)
    ];
    // Low (info only) : courantes dans apps légitimes et outils diagnostic
    // IsDebuggerPresent, OpenProcess, CreateProcess, ShellExecute, NtQueryInformationProcess, etc.

    if critical.iter().any(|s| import.contains(s)) {
        Severity::Critical
    } else if high.iter().any(|s| import.contains(s)) {
        Severity::High
    } else if medium.iter().any(|s| import.contains(s)) {
        Severity::Medium
    } else {
        Severity::Low // OpenProcess, CreateProcess, ShellExecute, IsDebuggerPresent, etc.
    }
}
