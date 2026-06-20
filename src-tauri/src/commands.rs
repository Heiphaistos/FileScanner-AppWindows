use std::path::{Path, PathBuf};
use std::time::Duration;

use tauri::State;
use tokio::sync::Mutex;

use crate::config::{clamav_updater, settings};
use crate::error::ScanError;
use crate::report::export;
use crate::report::types::{AppSettings, ScanResult};
use crate::scanner::clamav_db::{ClamavDb, ClamavStatus};
use crate::scanner::pipeline;

pub struct AppState {
    pub last_result: Mutex<Option<ScanResult>>,
}

/// Limite taille fichier : 2 Go
const MAX_FILE_SIZE: u64 = 2 * 1024 * 1024 * 1024;

/// Timeout global du pipeline de scan : 2 minutes
const SCAN_TIMEOUT_SECS: u64 = 120;

/// Valide un chemin entrant avant tout traitement.
///
/// Sécurité :
/// - Refuse les séquences `..` (path traversal)
/// - Canonicalise pour résoudre symlinks
/// - Vérifie que la cible est un fichier ordinaire (pas un device, pipe, dir)
/// - Vérifie la taille ≤ MAX_FILE_SIZE
fn validate_scan_path(raw: &str) -> Result<PathBuf, ScanError> {
    if raw.contains("..") {
        return Err(ScanError::Internal(
            "Chemin invalide : séquence '..' interdite".to_string(),
        ));
    }

    let canonical = Path::new(raw)
        .canonicalize()
        .map_err(|_| ScanError::AccessDenied("Chemin inaccessible ou inexistant".to_string()))?;

    if !canonical.is_file() {
        return Err(ScanError::Internal(
            "La cible n'est pas un fichier ordinaire".to_string(),
        ));
    }

    let size = std::fs::metadata(&canonical)
        .map_err(ScanError::Io)?
        .len();

    if size > MAX_FILE_SIZE {
        return Err(ScanError::Internal(format!(
            "Fichier trop volumineux ({} Go > 2 Go max)",
            size.checked_div(1_073_741_824).unwrap_or(0)
        )));
    }

    Ok(canonical)
}

/// Valide un chemin de destination d'export.
///
/// Sécurité :
/// - Refuse les séquences `..` (path traversal)
/// - Canonicalise le dossier parent pour résoudre les symlinks
/// - Restreint l'export au répertoire utilisateur (évite d'écrire dans System32 etc.)
/// - Whitelist d'extensions autorisées (évite d'écraser un .exe/.bat)
fn validate_export_path(raw: &str) -> Result<PathBuf, ScanError> {
    if raw.contains("..") {
        return Err(ScanError::ExportError(
            "Chemin invalide : séquence '..' interdite".to_string(),
        ));
    }

    let path = PathBuf::from(raw);

    // Le dossier parent doit exister et être canonicalisable
    let canonical_parent = if let Some(parent) = path.parent() {
        parent
            .canonicalize()
            .map_err(|_| ScanError::ExportError(format!(
                "Dossier de destination inexistant : {}",
                parent.display()
            )))?
    } else {
        return Err(ScanError::ExportError("Chemin invalide : pas de dossier parent".to_string()));
    };

    // Restreint au répertoire home de l'utilisateur
    let home = std::env::var("USERPROFILE")
        .or_else(|_| std::env::var("HOME"))
        .map(std::path::PathBuf::from)
        .map_err(|_| ScanError::ExportError("Impossible de déterminer le répertoire home".to_string()))?;

    if !canonical_parent.starts_with(&home) {
        return Err(ScanError::ExportError(
            "Le chemin d'export doit être dans le répertoire utilisateur".to_string(),
        ));
    }

    // Whitelist des extensions autorisées pour l'export
    let allowed_exts = ["json", "txt", "md", "html", "pdf"];
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");
    if !allowed_exts.contains(&ext) {
        return Err(ScanError::ExportError(format!(
            "Extension .{} non autorisée pour l'export (autorisées : json, txt, md, html, pdf)",
            ext
        )));
    }

    // Reconstruit le chemin canonicalisé : parent canonicalisé + nom de fichier
    let file_name = path
        .file_name()
        .ok_or_else(|| ScanError::ExportError("Nom de fichier manquant".to_string()))?;

    Ok(canonical_parent.join(file_name))
}

#[tauri::command]
pub async fn scan_file(
    file_path: String,
    state: State<'_, AppState>,
) -> Result<ScanResult, String> {
    // C1 — Validation stricte du chemin entrant
    let validated = validate_scan_path(&file_path).map_err(|e| e.to_string())?;

    let current_settings = settings::load().map_err(|e| e.to_string())?;

    // M3 — Timeout global 2 minutes
    let result = tokio::time::timeout(
        Duration::from_secs(SCAN_TIMEOUT_SECS),
        pipeline::scan_file(validated.to_str().unwrap_or(&file_path), &current_settings),
    )
    .await
    .map_err(|_| "Scan interrompu : timeout dépassé (2 minutes)".to_string())?
    .map_err(|e| e.to_string())?;

    *state.last_result.lock().await = Some(result.clone());
    Ok(result)
}

#[tauri::command]
pub async fn get_settings() -> Result<AppSettings, String> {
    settings::load().map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn save_settings(app_settings: AppSettings) -> Result<(), String> {
    // Validation des champs sensibles avant persistance dans le keystore
    if app_settings.vt_api_key.len() > 256 {
        return Err("Clé API VirusTotal trop longue (max 256 caractères)".to_string());
    }
    if app_settings.clamav_db_path.len() > 4096 {
        return Err("Chemin ClamAV trop long (max 4096 caractères)".to_string());
    }
    // Valider que le chemin ClamAV ne contient pas de séquences ..
    if app_settings.clamav_db_path.contains("..") {
        return Err("Chemin ClamAV invalide : séquence '..' interdite".to_string());
    }
    settings::save(&app_settings).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn export_report(
    result: ScanResult,
    format: String,
    output_path: String,
) -> Result<(), String> {
    // C2 — Validation chemin export
    let validated = validate_export_path(&output_path).map_err(|e| e.to_string())?;
    export::export(&result, &format, validated.to_str().unwrap_or(&output_path))
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn test_vt_key(api_key: String) -> Result<String, String> {
    if api_key.is_empty() {
        return Err("Clé API vide".to_string());
    }
    if api_key.len() > 256 {
        return Err("Clé API trop longue (max 256 caractères)".to_string());
    }
    crate::api::virustotal::test_key(&api_key)
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_clamav_status() -> Result<ClamavStatus, String> {
    let current = settings::load().map_err(|e| e.to_string())?;
    let db_dir = if current.clamav_db_path.is_empty() {
        clamav_updater::detect_local_clamav()
            .unwrap_or_else(clamav_updater::default_db_dir)
    } else {
        std::path::PathBuf::from(&current.clamav_db_path)
    };

    let db = ClamavDb::load(&db_dir).map_err(|e| e.to_string())?;
    Ok(db.status())
}

#[tauri::command]
pub async fn update_clamav_db() -> Result<Vec<String>, String> {
    let current = settings::load().map_err(|e| e.to_string())?;
    let db_dir = if current.clamav_db_path.is_empty() {
        clamav_updater::default_db_dir()
    } else {
        std::path::PathBuf::from(&current.clamav_db_path)
    };

    clamav_updater::download_databases(&db_dir)
        .await
        .map_err(|e| e.to_string())
}
