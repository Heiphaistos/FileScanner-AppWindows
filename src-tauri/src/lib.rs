pub mod ai {
    pub mod local_inference;
}
pub mod analyzer;
pub mod api {
    pub mod virustotal;
}
pub mod background;
pub mod commands;
pub mod commands_extra {
    pub mod quarantine;
}
pub mod config {
    pub mod clamav_updater;
    pub mod settings;
}
pub mod error;
pub mod report;
pub mod scanner;

use commands::AppState;
use tokio::sync::Mutex;

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_shell::init())
        .manage(AppState {
            last_result: Mutex::new(None),
        })
        .setup(|app| {
            // Feature A — Lance le worker de mise à jour ClamAV en arrière-plan
            background::updater::start(app.handle().clone());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::scan_file,
            commands::get_settings,
            commands::save_settings,
            commands::export_report,
            commands::get_clamav_status,
            commands::update_clamav_db,
            commands::test_vt_key,
            // Feature B — Quarantaine
            commands_extra::quarantine::quarantine_file,
        ])
        .run(tauri::generate_context!())
        .expect("Erreur au lancement de FileScanner");
}
