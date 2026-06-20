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
use serde::Serialize;

use crate::error::ScanError;

const QUARANTINE_KEY_FILE: &str = "quarantine.key";

#[derive(Serialize)]
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
        std::fs::write(&key_path, key.as_slice()).map_err(|e| e.to_string())?;

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

    // Créer le répertoire de quarantaine
    let qdir = quarantine_dir();
    std::fs::create_dir_all(&qdir).map_err(|e| e.to_string())?;

    // FIX C13 — Charger/créer la clé AES-256-GCM
    let key = get_or_create_key(&qdir).map_err(|e| e.to_string())?;

    // Lire et chiffrer avec AES-256-GCM
    let raw = std::fs::read(&source).map_err(|e| e.to_string())?;
    let encrypted = encrypt_quarantine(&raw, &key).map_err(|e| e.to_string())?;

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
        encryption: "AES-256-GCM".to_string(),
    };
    let meta_json = serde_json::to_string_pretty(&meta).map_err(|e| e.to_string())?;
    std::fs::write(&meta_path, meta_json).map_err(|e| e.to_string())?;

    // Supprimer le fichier original
    std::fs::remove_file(&source).map_err(|e| e.to_string())?;

    log::info!(
        "Fichier mis en quarantaine (AES-256-GCM) : {} → {}",
        source.display(),
        quar_path.display()
    );

    Ok(quar_path.display().to_string())
}
