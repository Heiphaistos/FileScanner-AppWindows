/// Feature A — Worker de mise à jour automatique ClamAV en arrière-plan.
///
/// Vérifie à l'ouverture si les bases sont périmées (> 24h) et déclenche
/// le téléchargement silencieusement. Émet des events Tauri vers le frontend.
use std::time::{Duration, SystemTime};

use tauri::{AppHandle, Emitter};

use crate::config::{clamav_updater, settings};

/// Seuil de péremption : 24 heures
const STALENESS_THRESHOLD_SECS: u64 = 24 * 60 * 60;

#[derive(Clone, serde::Serialize)]
pub struct UpdateEvent {
    pub status: String,   // "checking" | "up_to_date" | "updating" | "done" | "error"
    pub message: String,
    pub files: Vec<String>,
}

/// Lance le worker en arrière-plan (appelé depuis lib.rs `setup()`).
pub fn start(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        run_update_check(app).await;
    });
}

async fn run_update_check(app: AppHandle) {
    let _ = app.emit(
        "clamav://update-progress",
        UpdateEvent {
            status: "checking".to_string(),
            message: "Vérification des bases ClamAV…".to_string(),
            files: vec![],
        },
    );

    // Récupère le chemin DB depuis les settings
    let db_dir = match settings::load() {
        Ok(s) if !s.clamav_db_path.is_empty() => {
            std::path::PathBuf::from(&s.clamav_db_path)
        }
        _ => {
            clamav_updater::detect_local_clamav()
                .unwrap_or_else(clamav_updater::default_db_dir)
        }
    };

    // Vérifie l'âge du fichier daily.cvd
    let daily = db_dir.join("daily.cvd");
    if !needs_update(&daily) {
        let _ = app.emit(
            "clamav://update-progress",
            UpdateEvent {
                status: "up_to_date".to_string(),
                message: "Bases ClamAV à jour.".to_string(),
                files: vec![],
            },
        );
        return;
    }

    log::info!("Bases ClamAV périmées — mise à jour en arrière-plan");
    let _ = app.emit(
        "clamav://update-progress",
        UpdateEvent {
            status: "updating".to_string(),
            message: "Mise à jour des bases ClamAV en cours…".to_string(),
            files: vec![],
        },
    );

    match clamav_updater::download_databases(&db_dir).await {
        Ok(files) => {
            let _ = app.emit(
                "clamav://update-progress",
                UpdateEvent {
                    status: "done".to_string(),
                    message: format!("{} fichier(s) mis à jour.", files.len()),
                    files,
                },
            );
        }
        Err(e) => {
            log::warn!("Mise à jour ClamAV background échouée : {}", e);
            let _ = app.emit(
                "clamav://update-progress",
                UpdateEvent {
                    status: "error".to_string(),
                    message: format!("Échec mise à jour : {}", e),
                    files: vec![],
                },
            );
        }
    }
}

/// Retourne `true` si le fichier est absent ou plus vieux que STALENESS_THRESHOLD_SECS.
fn needs_update(path: &std::path::Path) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return true; // absent → besoin de télécharger
    };
    let Ok(modified) = meta.modified() else {
        return true;
    };
    let age = SystemTime::now()
        .duration_since(modified)
        .unwrap_or(Duration::from_secs(u64::MAX));
    age.as_secs() > STALENESS_THRESHOLD_SECS
}
