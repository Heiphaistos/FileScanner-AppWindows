use std::path::Path;

use crate::ai::local_inference::LocalInference;
use crate::analyzer::{hash, mime, pe_parser, script_parser};
use crate::api::virustotal;
use crate::config::clamav_updater;
use crate::error::ScanError;
use crate::report::types::{AppSettings, ClamavResult, IoC, ScanResult, Severity, Verdict};
use crate::scanner::clamav_db::ClamavDb;
use crate::scanner::yara_engine::YaraEngine;

pub async fn scan_file(file_path: &str, settings: &AppSettings) -> Result<ScanResult, ScanError> {
    let path = Path::new(file_path);

    if !path.exists() {
        return Err(ScanError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("Fichier introuvable : {}", file_path),
        )));
    }

    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .to_string();

    let file_size = std::fs::metadata(path)?.len();

    // 1. Hash streaming
    let hashes = hash::compute(path)?;

    // 2. MIME réel
    let mime_type = mime::detect(path);
    let category = mime::categorize(&mime_type, path);

    // 3. Lecture binaire pour analyse
    let raw_bytes = std::fs::read(path)?;

    // 4. Analyse PE ou Script selon catégorie
    let mut pe_info = None;
    let mut script_info = None;
    let mut ioc_list = Vec::new();

    match category {
        mime::FileCategory::Pe => {
            match pe_parser::parse(path, &raw_bytes) {
                Ok((info, iocs)) => {
                    ioc_list.extend(iocs);
                    pe_info = Some(info);
                }
                Err(e) => {
                    log::warn!("Analyse PE échouée pour {} : {}", file_name, e);
                }
            }
        }
        mime::FileCategory::Script => {
            if let Ok(content) = std::str::from_utf8(&raw_bytes) {
                let (info, iocs) = script_parser::analyze(path, content);
                ioc_list.extend(iocs);
                script_info = Some(info);
            }
        }
        _ => {}
    }

    // 5. YARA scan
    let yara = YaraEngine::new();
    let yara_matches = yara.scan(&raw_bytes);

    // 6. ClamAV local database
    let clamav = {
        let db_dir = if settings.clamav_db_path.is_empty() {
            // Auto-detect : installation locale ou répertoire par défaut
            clamav_updater::detect_local_clamav()
                .unwrap_or_else(clamav_updater::default_db_dir)
        } else {
            std::path::PathBuf::from(&settings.clamav_db_path)
        };

        match ClamavDb::load(&db_dir) {
            Ok(db) if db.status().loaded => {
                let hit = db
                    .check_md5(&hashes.md5)
                    .or_else(|| db.check_sha256(&hashes.sha256));
                if let Some(m) = hit {
                    ioc_list.push(IoC {
                        ioc_type: "ClamAV".to_string(),
                        value: m.malware_name.clone(),
                        severity: Severity::Critical,
                        description: format!("Détecté par {} (base ClamAV)", m.database),
                    });
                    Some(ClamavResult {
                        malware_name: m.malware_name,
                        database: m.database,
                    })
                } else {
                    None
                }
            }
            _ => None,
        }
    };

    // 7. VirusTotal (si clé API disponible)
    let virustotal = if !settings.vt_api_key.is_empty() {
        match virustotal::lookup(&hashes.sha256, &settings.vt_api_key).await {
            Ok(result) => Some(result),
            Err(ScanError::Internal(msg)) if msg.contains("inconnu") => None,
            Err(e) => {
                log::warn!("VirusTotal lookup échoué : {}", e);
                None
            }
        }
    } else {
        None
    };

    // 8. Score de dangerosité agrégé
    let verdict_score = compute_score(
        pe_info.as_ref(),
        script_info.as_ref(),
        virustotal.as_ref(),
        &yara_matches,
        clamav.is_some(),
    );

    // 9. IA locale
    let ai = LocalInference::new();
    let ai_verdict = if settings.ai_enabled {
        ai.evaluate(verdict_score, pe_info.as_ref(), script_info.as_ref(), &yara_matches)
    } else {
        None
    };

    // 10. Verdict final
    let verdict = determine_verdict(verdict_score);

    Ok(ScanResult {
        file_path: file_path.to_string(),
        file_name,
        file_size,
        mime_type,
        hashes,
        verdict,
        verdict_score,
        pe_info,
        script_info,
        virustotal,
        clamav,
        yara_matches,
        ai_verdict,
        ioc_list,
        scanned_at: chrono::Utc::now().to_rfc3339(),
    })
}

fn compute_score(
    pe_info: Option<&crate::report::types::PeInfo>,
    script_info: Option<&crate::report::types::ScriptInfo>,
    vt: Option<&crate::report::types::VtResult>,
    yara_matches: &[crate::report::types::YaraMatch],
    clamav_hit: bool,
) -> u8 {
    let mut score: u32 = 0;

    // ClamAV hit → malveillant certain
    if clamav_hit {
        score = score.max(95);
    }

    // VT : poids le plus fort
    if let Some(vt) = vt {
        if vt.positives >= 10 {
            score = score.max(95);
        } else if vt.positives >= 3 {
            score = score.max(85);
        } else if vt.positives >= 1 {
            score = score.max(60);
        }
    }

    // YARA matches — score additif plafonné (évite qu'1 seul match = verdict final)
    // 1 règle Critical = +35pts, High = +20pts, Medium = +10pts, Low = +5pts
    // Plusieurs règles s'accumulent → score monte naturellement
    for m in yara_matches {
        use crate::report::types::Severity;
        let delta: u32 = match m.severity {
            Severity::Critical => 35,
            Severity::High => 20,
            Severity::Medium => 10,
            Severity::Low => 5,
        };
        score = (score + delta).min(100);
    }

    // PE indicateurs
    if let Some(pe) = pe_info {
        // Entropie : Tauri/Electron bundlent assets compressés → entropie élevée normale
        // max(45) au lieu de max(65) pour éviter FP sur apps légitimes compressées
        if pe.entropy_max > 7.8 {
            score = (score + 20).min(100); // additif, pas max() — accumule avec le reste
        } else if pe.entropy_max > 7.5 {
            score = (score + 10).min(100);
        } else if pe.entropy_max > 7.2 {
            score = (score + 5).min(100);
        }
        // Scoring imports : seulement Critical et High (Medium/Low = info only, pas de score)
        // Low = OpenProcess, CreateProcess, ShellExecute, etc. = légitimes pour outils diagnostic
        if !pe.suspicious_imports.is_empty() {
            // On ne peut pas appeler classify_import_severity ici (dans pipeline),
            // donc on utilise les mêmes listes critères que pe_parser
            let critical_imports = &[
                "CreateRemoteThread", "WriteProcessMemory",
                "NtUnmapViewOfSection", "ZwUnmapViewOfSection",
            ];
            let high_imports = &[
                "VirtualAllocEx", "SetWindowsHookEx", "URLDownloadToFile", "WinExec",
            ];
            let import_score: u32 = pe.suspicious_imports.iter().map(|imp| {
                if critical_imports.iter().any(|s| imp.contains(s)) { 20 }
                else if high_imports.iter().any(|s| imp.contains(s)) { 10 }
                else { 0 } // Medium/Low = 0 pts
            }).sum::<u32>().min(40);
            score = (score + import_score).min(100);
        }
    }

    // Script indicateurs
    if let Some(script) = script_info {
        if script.obfuscation_detected {
            score = score.max(60);
        }
        let call_score = (script.dangerous_calls.len() as u32 * 8).min(60);
        score = score.max(call_score);
    }

    score.min(100) as u8
}

fn determine_verdict(score: u8) -> Verdict {
    match score {
        0..=25 => Verdict::Safe,
        26..=64 => Verdict::Suspicious,
        65..=100 => Verdict::Malicious,
        _ => Verdict::Unknown,
    }
}
