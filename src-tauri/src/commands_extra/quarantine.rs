/// Feature B — Quarantaine de fichier malveillant.
///
/// Protocole :
/// 1. Valide le chemin source
/// 2. Lit le fichier en bytes
/// 3. XOR chaque byte avec 0xAB (neutralise l'exécution accidentelle)
/// 4. Écrit le fichier chiffré dans %APPDATA%\FileScanner\quarantine\{sha256}.quar
/// 5. Écrit les métadonnées dans %APPDATA%\FileScanner\quarantine\{sha256}.meta.json
/// 6. Supprime le fichier original
use std::path::{Path, PathBuf};

use chrono::Utc;
use serde::Serialize;

use crate::error::ScanError;

const XOR_KEY: u8 = 0xAB;

#[derive(Serialize)]
struct QuarantineMeta {
    original_path: String,
    sha256: String,
    quarantine_date: String,
    size_bytes: u64,
    xor_key: u8,
}

/// Répertoire de quarantaine : %APPDATA%\FileScanner\quarantine\
fn quarantine_dir() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("FileScanner")
        .join("quarantine")
}

/// Valide le chemin source (réutilise la même logique que commands.rs).
fn validate_source(raw: &str) -> Result<PathBuf, ScanError> {
    if raw.contains("..") {
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

#[tauri::command]
pub async fn quarantine_file(file_path: String, sha256: String) -> Result<String, String> {
    // Validation sha256 (64 hex chars)
    if sha256.len() != 64 || !sha256.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("sha256 invalide".to_string());
    }

    let source = validate_source(&file_path).map_err(|e| e.to_string())?;

    let size_bytes = std::fs::metadata(&source)
        .map_err(|e| e.to_string())?
        .len();

    // Lire et XOR-chiffrer les bytes
    let raw = std::fs::read(&source).map_err(|e| e.to_string())?;
    let encrypted: Vec<u8> = raw.iter().map(|b| b ^ XOR_KEY).collect();

    // Créer le répertoire de quarantaine
    let qdir = quarantine_dir();
    std::fs::create_dir_all(&qdir).map_err(|e| e.to_string())?;

    let quar_path = qdir.join(format!("{}.quar", sha256));
    let meta_path = qdir.join(format!("{}.meta.json", sha256));

    // Écrire le fichier chiffré
    std::fs::write(&quar_path, &encrypted).map_err(|e| e.to_string())?;

    // Écrire les métadonnées JSON
    let meta = QuarantineMeta {
        original_path: source.display().to_string(),
        sha256: sha256.clone(),
        quarantine_date: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        size_bytes,
        xor_key: XOR_KEY,
    };
    let meta_json = serde_json::to_string_pretty(&meta).map_err(|e| e.to_string())?;
    std::fs::write(&meta_path, meta_json).map_err(|e| e.to_string())?;

    // Supprimer le fichier original
    std::fs::remove_file(&source).map_err(|e| e.to_string())?;

    log::info!(
        "Fichier mis en quarantaine : {} → {}",
        source.display(),
        quar_path.display()
    );

    Ok(quar_path.display().to_string())
}
