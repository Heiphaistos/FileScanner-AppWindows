/// Téléchargement des bases ClamAV depuis le miroir officiel.
///
/// Protocole ClamAV CDN :
///   https://database.clamav.net/main.cvd   (~170MB) — base principale
///   https://database.clamav.net/daily.cvd  (~70MB)  — mise à jour quotidienne
///
/// Optionnel : permettre à l'utilisateur de pointer vers son installation ClamAV locale
/// (ex: C:\ProgramData\ClamAV\) — évite de re-télécharger.
use std::path::{Path, PathBuf};

use reqwest::Client;
use serde::{Deserialize, Serialize};

use crate::error::ScanError;

// Miroir officiel Microsoft : database.clamav.net renvoie 403 (CloudFlare bot
// management) aux clients non-freshclam, dont notre user-agent custom.
const CDN_BASE: &str = "https://packages.microsoft.com/clamav";
const DATABASES: &[(&str, &str)] = &[
    ("main.cvd", "Base principale ClamAV"),
    ("daily.cvd", "Mise à jour quotidienne"),
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateProgress {
    pub file: String,
    pub downloaded_bytes: u64,
    pub total_bytes: Option<u64>,
    pub done: bool,
}

/// Retourne le chemin par défaut de la DB ClamAV (données app)
pub fn default_db_dir() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("FileScanner")
        .join("clamav_db")
}

/// Télécharge les bases ClamAV vers db_dir.
/// Retourne la liste des fichiers téléchargés.
pub async fn download_databases(db_dir: &Path) -> Result<Vec<String>, ScanError> {
    std::fs::create_dir_all(db_dir)?;

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(600))
        .user_agent("FileScanner/1.0 (ClamAV database client)")
        .build()?;

    let mut downloaded = Vec::new();

    for (filename, _description) in DATABASES {
        let url = format!("{}/{}", CDN_BASE, filename);
        let dest = db_dir.join(filename);

        log::info!("Téléchargement ClamAV : {}", url);

        let response = client.get(&url).send().await?;

        if !response.status().is_success() {
            log::warn!(
                "Échec téléchargement {} : HTTP {}",
                filename,
                response.status()
            );
            continue;
        }

        let bytes = response.bytes().await?;
        std::fs::write(&dest, &bytes)?;
        log::info!("Écrit {} ({} octets)", dest.display(), bytes.len());
        downloaded.push(filename.to_string());
    }

    Ok(downloaded)
}

/// Détecte si ClamAV est installé localement et retourne le chemin de sa DB.
/// Priorité au dossier `clamav_db` à côté de l'exe (mode portable, bases embarquées).
pub fn detect_local_clamav() -> Option<PathBuf> {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let portable = dir.join("clamav_db");
            if portable.exists() && has_cvd_files(&portable) {
                return Some(portable);
            }
        }
    }
    let candidates = &[
        r"C:\ProgramData\ClamAV",
        r"C:\Program Files\ClamAV\db",
        r"C:\Program Files (x86)\ClamAV\db",
    ];
    for candidate in candidates {
        let path = PathBuf::from(candidate);
        if path.exists() && has_cvd_files(&path) {
            return Some(path);
        }
    }
    None
}

fn has_cvd_files(dir: &Path) -> bool {
    std::fs::read_dir(dir)
        .map(|entries| {
            entries.flatten().any(|e| {
                e.path()
                    .extension()
                    .and_then(|x| x.to_str())
                    .map(|x| matches!(x, "cvd" | "cld" | "hdb" | "msb"))
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false)
}
