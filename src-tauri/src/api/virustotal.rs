use std::time::Duration;

use reqwest::Client;
use serde::Deserialize;

use crate::error::ScanError;
use crate::report::types::VtResult;

const VT_API_BASE: &str = "https://www.virustotal.com/api/v3";

/// H2 — Nombre de tentatives max en cas de 429 / erreur réseau transitoire.
const MAX_RETRIES: u32 = 3;

#[derive(Deserialize)]
struct VtResponse {
    data: VtData,
}

#[derive(Deserialize)]
struct VtData {
    attributes: VtAttributes,
}

#[derive(Deserialize)]
struct VtAttributes {
    last_analysis_stats: VtStats,
    last_analysis_results: Option<std::collections::HashMap<String, VtEngineResult>>,
    last_analysis_date: Option<i64>,
}

#[derive(Deserialize)]
struct VtStats {
    malicious: u32,
    suspicious: u32,
    undetected: u32,
    #[serde(default)]
    harmless: u32,
}

#[derive(Deserialize)]
struct VtEngineResult {
    category: String,
    result: Option<String>,
}

/// H2 — Backoff exponentiel : attend 500ms * 2^attempt entre chaque tentative.
/// Ne retente que sur RateLimited (429) ; les autres erreurs sont propagées immédiatement.
async fn with_backoff<F, Fut, T>(mut f: F) -> Result<T, ScanError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, ScanError>>,
{
    for attempt in 0..MAX_RETRIES {
        match f().await {
            Ok(v) => return Ok(v),
            Err(ScanError::RateLimited) if attempt < MAX_RETRIES - 1 => {
                let delay_ms = 500 * 2u64.pow(attempt);
                log::warn!(
                    "VT quota dépassé (429), tentative {}/{} — attente {}ms",
                    attempt + 1,
                    MAX_RETRIES,
                    delay_ms
                );
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
            }
            Err(e) => return Err(e),
        }
    }
    Err(ScanError::RateLimited)
}

pub async fn test_key(api_key: &str) -> Result<String, ScanError> {
    if api_key.is_empty() {
        return Err(ScanError::Internal("Clé API vide".to_string()));
    }
    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;
    // EICAR hash — toujours présent dans VT ; 200=clé valide, 401=invalide, 429=quota dépassé
    const EICAR: &str = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
    let resp = client
        .get(format!("{VT_API_BASE}/files/{EICAR}"))
        .header("x-apikey", api_key)
        .send()
        .await?;
    match resp.status().as_u16() {
        200 => Ok("Clé API valide ✓  (EICAR détecté dans VT)".to_string()),
        401 => Err(ScanError::Internal("Clé invalide ou expirée (401)".to_string())),
        403 => Err(ScanError::Internal("Accès refusé — clé incorrecte (403)".to_string())),
        429 => Ok("Clé valide, quota quotidien dépassé (429)".to_string()),
        404 => Ok("Clé API valide ✓".to_string()),
        n => Err(ScanError::Internal(format!("Erreur HTTP {n}"))),
    }
}

pub async fn lookup(sha256: &str, api_key: &str) -> Result<VtResult, ScanError> {
    if api_key.is_empty() {
        return Err(ScanError::MissingApiKey);
    }

    let client = Client::builder()
        .timeout(Duration::from_secs(15))
        .build()?;

    // H2 — Wrapped dans backoff exponentiel
    let response = with_backoff(|| {
        let client = client.clone();
        let url = format!("{}/files/{}", VT_API_BASE, sha256);
        let key = api_key.to_string();
        async move {
            let resp = client
                .get(&url)
                .header("x-apikey", &key)
                .send()
                .await
                .map_err(ScanError::HttpError)?;

            match resp.status().as_u16() {
                429 => Err(ScanError::RateLimited),
                404 => Err(ScanError::Internal("Fichier inconnu de VirusTotal".to_string())),
                s if s >= 400 => Err(ScanError::Internal(format!(
                    "VirusTotal API erreur HTTP {s}"
                ))),
                _ => Ok(resp),
            }
        }
    })
    .await?;

    let vt: VtResponse = response.json().await?;
    let stats = &vt.data.attributes.last_analysis_stats;
    let total = stats.malicious + stats.suspicious + stats.undetected + stats.harmless;

    let detection_names: Vec<String> = vt
        .data
        .attributes
        .last_analysis_results
        .unwrap_or_default()
        .values()
        .filter(|r| r.category == "malicious")
        .filter_map(|r| r.result.clone())
        .collect();

    let scan_date = vt
        .data
        .attributes
        .last_analysis_date
        .map(|ts| {
            use chrono::TimeZone;
            chrono::Utc
                .timestamp_opt(ts, 0)
                .single()
                .map(|dt| dt.format("%Y-%m-%d %H:%M UTC").to_string())
                .unwrap_or_default()
        })
        .unwrap_or_default();

    Ok(VtResult {
        positives: stats.malicious,
        total,
        permalink: format!("https://www.virustotal.com/gui/file/{}", sha256),
        scan_date,
        detection_names,
    })
}
