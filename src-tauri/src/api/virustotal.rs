use reqwest::Client;
use serde::Deserialize;

use crate::error::ScanError;
use crate::report::types::VtResult;

const VT_API_BASE: &str = "https://www.virustotal.com/api/v3";

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

pub async fn test_key(api_key: &str) -> Result<String, ScanError> {
    if api_key.is_empty() {
        return Err(ScanError::Internal("Clé API vide".to_string()));
    }
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(10))
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
        .timeout(std::time::Duration::from_secs(15))
        .build()?;

    let url = format!("{}/files/{}", VT_API_BASE, sha256);
    let response = client
        .get(&url)
        .header("x-apikey", api_key)
        .send()
        .await?;

    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Err(ScanError::Internal("Fichier inconnu de VirusTotal".to_string()));
    }

    if !response.status().is_success() {
        return Err(ScanError::Internal(format!(
            "VirusTotal API erreur HTTP {}",
            response.status()
        )));
    }

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
