use tauri::State;
use tokio::sync::Mutex;

use crate::config::{clamav_updater, settings};
use crate::report::export;
use crate::report::types::{AppSettings, ScanResult};
use crate::scanner::clamav_db::{ClamavDb, ClamavStatus};
use crate::scanner::pipeline;

pub struct AppState {
    pub last_result: Mutex<Option<ScanResult>>,
}

#[tauri::command]
pub async fn scan_file(
    file_path: String,
    state: State<'_, AppState>,
) -> Result<ScanResult, String> {
    let current_settings = settings::load().map_err(|e| e.to_string())?;
    let result = pipeline::scan_file(&file_path, &current_settings)
        .await
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
    settings::save(&app_settings).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn export_report(
    result: ScanResult,
    format: String,
    output_path: String,
) -> Result<(), String> {
    export::export(&result, &format, &output_path).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn test_vt_key(api_key: String) -> Result<String, String> {
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
