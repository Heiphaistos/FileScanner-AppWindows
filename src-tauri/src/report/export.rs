//! export.rs — Construit le rapport complet d'un scan (modèle `report::Doc`) et le
//! rend en Markdown, PDF, texte, HTML ou JSON. Tous les formats partagent le même
//! contenu : verdict chiffré, raisons pour/contre, réputation en ligne, chaque
//! détection expliquée avec le détail de son pourcentage, et les données techniques.

use crate::api::intel::IntelStatus;
use crate::error::ScanError;
use crate::report::types::{Detection, ScanResult, Severity, Verdict};
use crate::report::{self, Badge, Block, Cell, Doc, Tone};

pub fn severity_label(s: &Severity) -> &'static str {
    match s {
        Severity::Low => "FAIBLE",
        Severity::Medium => "MOYENNE",
        Severity::High => "ÉLEVÉE",
        Severity::Critical => "CRITIQUE",
    }
}

fn severity_tone(s: &Severity) -> Tone {
    match s {
        Severity::Low => Tone::Neutral,
        Severity::Medium => Tone::Warn,
        Severity::High => Tone::Danger,
        Severity::Critical => Tone::Critical,
    }
}

fn verdict_label(v: &Verdict) -> (&'static str, Tone) {
    match v {
        Verdict::Safe => ("SAIN", Tone::Good),
        Verdict::Suspicious => ("SUSPECT", Tone::Warn),
        Verdict::Malicious => ("MALVEILLANT", Tone::Critical),
        Verdict::Unknown => ("INDÉTERMINÉ", Tone::Neutral),
    }
}

fn intel_label(s: IntelStatus) -> (&'static str, Tone) {
    match s {
        IntelStatus::Malicious => ("MALVEILLANT", Tone::Critical),
        IntelStatus::Suspicious => ("SUSPECT", Tone::Warn),
        IntelStatus::Clean => ("RIEN TROUVÉ", Tone::Good),
        IntelStatus::KnownGood => ("LÉGITIME CONNU", Tone::Good),
        IntelStatus::NotFound => ("INCONNU", Tone::Neutral),
        IntelStatus::Error => ("INDISPONIBLE", Tone::Neutral),
        IntelStatus::NotConfigured => ("NON CONFIGURÉ", Tone::Neutral),
    }
}

pub fn format_bytes(n: u64) -> String {
    if n < 1024 {
        format!("{n} o")
    } else if n < 1024 * 1024 {
        format!("{:.1} Ko", n as f64 / 1024.0)
    } else {
        format!("{:.2} Mo", n as f64 / (1024.0 * 1024.0))
    }
}

fn pretty_date(rfc3339: &str) -> String {
    chrono::DateTime::parse_from_rfc3339(rfc3339)
        .map(|d| d.with_timezone(&chrono::Utc).format("%d/%m/%Y à %H:%M:%S UTC").to_string())
        .unwrap_or_else(|_| rfc3339.to_string())
}

fn detection_card(i: usize, d: &Detection) -> Block {
    let threat = Tone::for_threat(d.confidence);
    let mut calc = vec![format!("Probabilité de départ pour ce type de signal : {} %", d.base_confidence)];
    for f in &d.factors {
        calc.push(format!("{:+} points : {}", f.delta, f.label));
    }
    calc.push(format!(
        "Résultat : {} % de risque réel → {} % de probabilité de faux positif",
        d.confidence, d.false_positive
    ));

    let mut body = vec![
        Block::Meter { label: "Probabilité de menace réelle".into(), percent: d.confidence, tone: threat },
        Block::Meter { label: "Probabilité de faux positif".into(), percent: d.false_positive, tone: Tone::Good },
        Block::KeyValues {
            items: vec![
                ("Conclusion".into(), d.verdict.clone()),
                ("Origine".into(), d.source.clone()),
                ("Gravité si réel".into(), severity_label(&d.severity).to_string()),
            ]
            .into_iter()
            .chain((!d.value.is_empty()).then(|| ("Élément".to_string(), d.value.clone())))
            .collect(),
            mono: false,
        },
        Block::Heading(2, "Ce que ça fait".into()),
        Block::Para(d.what_it_does.clone()),
        Block::Heading(2, "Pourquoi ça peut être malveillant".into()),
        Block::Para(d.why_malicious.clone()),
        Block::Heading(2, "Pourquoi ça peut être légitime (faux positif)".into()),
        Block::Para(d.why_legitimate.clone()),
        Block::Heading(2, "Calcul du pourcentage".into()),
        Block::Bullets(calc),
    ];
    if !d.evidence.is_empty() {
        body.push(Block::Heading(2, "Preuves trouvées dans le fichier".into()));
        body.push(Block::Code(d.evidence.iter().take(12).cloned().collect::<Vec<_>>().join("\n")));
    }
    Block::Card {
        tone: threat,
        title: format!("{}. {}", i + 1, d.title),
        badges: vec![
            Badge { text: format!("Menace {} %", d.confidence), tone: threat },
            Badge { text: format!("Faux positif {} %", d.false_positive), tone: Tone::Good },
        ],
        body,
    }
}

pub fn build(r: &ScanResult) -> Doc {
    let a = &r.assessment;
    let (vlabel, vtone) = verdict_label(&r.verdict);
    let p = a.malicious_probability;
    let mut b: Vec<Block> = Vec::new();

    // ── Verdict ──
    let mut lines = vec![a.summary.clone()];
    if let Some(cl) = &r.clamav {
        lines.push(format!("ClamAV : {} ({})", cl.malware_name, cl.database));
    }
    b.push(Block::Callout {
        tone: vtone,
        title: format!("Verdict : {vlabel} — {}", if a.label.is_empty() { "—" } else { &a.label }),
        lines,
    });
    let consulted = r
        .intel
        .iter()
        .filter(|s| !matches!(s.status, IntelStatus::NotConfigured | IntelStatus::Error))
        .count();
    b.push(Block::Stats(vec![
        (format!("{p} %"), "Probabilité de menace réelle".into(), Tone::for_threat(p)),
        (
            if r.detections.is_empty() { "—".into() } else { format!("{} %", a.false_positive_probability) },
            "Probabilité de faux positif".into(),
            Tone::Good,
        ),
        (r.detections.len().to_string(), "Éléments détectés".into(), if r.detections.is_empty() { Tone::Good } else { Tone::Info }),
        (format!("{consulted}/{}", r.intel.len()), "Bases en ligne consultées".into(), Tone::Info),
    ]));
    b.push(Block::Meter { label: "Probabilité que le fichier soit réellement malveillant".into(), percent: p, tone: Tone::for_threat(p) });
    if !r.detections.is_empty() {
        b.push(Block::Meter {
            label: "Probabilité que les alertes soient des faux positifs".into(),
            percent: a.false_positive_probability,
            tone: Tone::Good,
        });
    }

    // ── Explication ──
    if !r.explanation.trim().is_empty() {
        b.push(Block::Heading(1, "Explication en clair".into()));
        let mut bullets = Vec::new();
        for line in r.explanation.lines().map(str::trim).filter(|l| !l.is_empty()) {
            if let Some(x) = line.strip_prefix("• ") {
                bullets.push(x.to_string());
            } else {
                if !bullets.is_empty() {
                    b.push(Block::Bullets(std::mem::take(&mut bullets)));
                }
                b.push(Block::Para(line.to_string()));
            }
        }
        if !bullets.is_empty() {
            b.push(Block::Bullets(bullets));
        }
    }
    if !a.reasons_malicious.is_empty() {
        b.push(Block::Heading(2, "Arguments en faveur d'une menace réelle".into()));
        b.push(Block::Bullets(a.reasons_malicious.clone()));
    }
    // L'explication reprend déjà ces arguments quand la menace n'est pas quasi certaine.
    let already = a.reasons_legitimate.first().is_some_and(|x| r.explanation.contains(x.as_str()));
    if !a.reasons_legitimate.is_empty() && !already {
        b.push(Block::Heading(2, "Arguments en faveur d'un faux positif / fichier légitime".into()));
        b.push(Block::Bullets(a.reasons_legitimate.clone()));
    }

    // ── Fichier ──
    b.push(Block::Heading(1, "Fichier analysé".into()));
    b.push(Block::KeyValues {
        items: vec![
            ("Nom".into(), r.file_name.clone()),
            ("Chemin".into(), r.file_path.clone()),
            ("Taille".into(), format!("{} ({} octets)", format_bytes(r.file_size), r.file_size)),
            ("Type réel (MIME)".into(), r.mime_type.clone()),
            ("Catégorie".into(), r.category.clone()),
            ("Analysé le".into(), pretty_date(&r.scanned_at)),
        ],
        mono: false,
    });
    b.push(Block::KeyValues {
        items: vec![
            ("MD5".into(), r.hashes.md5.clone()),
            ("SHA-256".into(), r.hashes.sha256.clone()),
        ],
        mono: true,
    });

    // ── Réputation en ligne ──
    b.push(Block::Heading(1, format!("Réputation en ligne ({} bases)", r.intel.len())));
    b.push(Block::Note(
        "Seule l'empreinte du fichier (SHA-256 / MD5) est envoyée à ces services, jamais le fichier lui-même. \
         « Inconnu » est normal pour un fichier personnel, récent ou peu diffusé."
            .into(),
    ));
    let queried: Vec<_> = r.intel.iter().filter(|s| s.status != IntelStatus::NotConfigured).collect();
    let unconfigured: Vec<_> = r.intel.iter().filter(|s| s.status == IntelStatus::NotConfigured).collect();
    if queried.is_empty() {
        b.push(Block::Para("Aucune base en ligne n'a été interrogée pour ce scan.".into()));
    } else {
        let rows = queried
            .iter()
            .map(|s| {
                let (lab, tone) = intel_label(s.status);
                let mut det = s.summary.clone();
                if !s.threat_names.is_empty() {
                    det.push_str(&format!("\nNoms : {}", s.threat_names.join(", ")));
                }
                for d in s.details.iter().take(4) {
                    det.push('\n');
                    det.push_str(d);
                }
                if let Some(l) = &s.link {
                    det.push_str(&format!("\n{l}"));
                }
                vec![Cell::new(format!("{}\n{}", s.source, s.kind)), Cell::toned(lab, tone), Cell::new(det)]
            })
            .collect();
        b.push(Block::Table {
            headers: vec!["Source".into(), "Résultat".into(), "Détails".into()],
            rows,
            widths: vec![2.2, 1.4, 5.4],
        });
    }
    if !unconfigured.is_empty() {
        let names: Vec<String> = unconfigured
            .iter()
            .map(|s| {
                let key = s.summary.split('(').nth(1).and_then(|x| x.split(')').next()).unwrap_or("");
                if key.is_empty() { s.source.clone() } else { format!("{} ({key})", s.source) }
            })
            .collect();
        b.push(Block::Note(format!(
            "Bases non interrogées faute de clé API dans les réglages : {}.",
            names.join(", ")
        )));
    }
    if let Some(vt) = &r.virustotal {
        b.push(Block::Heading(2, "VirusTotal — détail".into()));
        let mut kv = vec![
            (
                "Détections".into(),
                format!(
                    "{} malveillant(s), {} suspect(s), {} sans détection, sur {} moteurs",
                    vt.positives, vt.suspicious, vt.undetected + vt.harmless, vt.total
                ),
            ),
            ("Dernière analyse".into(), vt.scan_date.clone()),
        ];
        if let Some(l) = &vt.popular_threat_label {
            kv.push(("Famille la plus citée".into(), l.clone()));
        }
        if let Some(t) = &vt.type_description {
            kv.push(("Type".into(), t.clone()));
        }
        if let Some(sig) = &vt.signature {
            kv.push(("Signature".into(), format!("{} — {}", sig.verified, sig.signers)));
            if !sig.product.is_empty() {
                kv.push(("Produit".into(), sig.product.clone()));
            }
        }
        if let Some(tv) = &vt.trusted_verdict {
            kv.push(("Verdict de confiance".into(), tv.clone()));
        }
        if let Some(f) = &vt.first_submission {
            kv.push(("Première soumission".into(), format!("{f} ({} soumissions)", vt.times_submitted)));
        }
        if !vt.names.is_empty() {
            kv.push(("Noms connus".into(), vt.names.join(", ")));
        }
        if !vt.tags.is_empty() {
            kv.push(("Étiquettes".into(), vt.tags.join(", ")));
        }
        if !vt.sandbox_verdicts.is_empty() {
            kv.push(("Sandboxes".into(), vt.sandbox_verdicts.join(" ; ")));
        }
        if !vt.crowdsourced_yara.is_empty() {
            kv.push(("Règles YARA publiques".into(), vt.crowdsourced_yara.join(", ")));
        }
        kv.push(("Lien".into(), vt.permalink.clone()));
        b.push(Block::KeyValues { items: kv, mono: false });
        if !vt.engines.is_empty() {
            b.push(Block::Table {
                headers: vec!["Antivirus".into(), "Classement".into(), "Nom de détection".into()],
                rows: vt
                    .engines
                    .iter()
                    .map(|e| {
                        let (c, t) = if e.category == "malicious" { ("Malveillant", Tone::Critical) } else { ("Suspect", Tone::Warn) };
                        vec![Cell::new(e.engine.clone()), Cell::toned(c, t), Cell::mono(e.result.clone())]
                    })
                    .collect(),
                widths: vec![2.0, 1.4, 4.0],
            });
        }
    }

    // ── Détections ──
    b.push(Block::Heading(1, format!("Détections détaillées ({})", r.detections.len())));
    if r.detections.is_empty() {
        b.push(Block::Para("Aucun élément suspect n'a été détecté dans ce fichier.".into()));
    } else {
        b.push(Block::Note(
            "Pour chaque élément : ce qu'il fait, pourquoi un malware l'utiliserait, pourquoi un logiciel légitime \
             l'utiliserait aussi, et le calcul détaillé de sa probabilité. « Gravité » = impact SI la menace est réelle ; \
             « Menace » = probabilité qu'elle le soit."
                .into(),
        ));
        b.push(Block::Table {
            headers: vec!["#".into(), "Élément".into(), "Menace".into(), "Faux positif".into(), "Conclusion".into()],
            rows: r
                .detections
                .iter()
                .enumerate()
                .map(|(i, d)| {
                    vec![
                        Cell::new((i + 1).to_string()),
                        Cell::new(d.title.clone()),
                        Cell::toned(format!("{} %", d.confidence), Tone::for_threat(d.confidence)),
                        Cell::new(format!("{} %", d.false_positive)),
                        Cell::new(d.verdict.clone()),
                    ]
                })
                .collect(),
            widths: vec![0.5, 5.0, 1.1, 1.2, 3.0],
        });
        for (i, d) in r.detections.iter().enumerate() {
            b.push(detection_card(i, d));
        }
    }

    // ── Données techniques ──
    b.push(Block::Heading(1, "Données techniques".into()));
    if let Some(bin) = &r.pe_info {
        b.push(Block::Heading(2, "Exécutable PE".into()));
        b.push(Block::KeyValues {
            items: vec![
                ("Architecture".into(), if bin.is_64bit { "64 bits".into() } else { "32 bits".into() }),
                ("Signature numérique".into(), if bin.is_signed { "Présente (non vérifiée localement)".into() } else { "Absente".into() }),
                ("Compressé / protégé".into(), if bin.is_packed { "Probable".into() } else { "Non détecté".into() }),
                ("Point d'entrée".into(), format!("0x{:x}", bin.entry_point)),
                ("Entropie maximale".into(), format!("{:.2} / 8", bin.entropy_max)),
                ("Fonctions importées".into(), format!("{} ({} sensibles)", bin.imports.len(), bin.suspicious_imports.len())),
            ],
            mono: false,
        });
        if !bin.sections.is_empty() {
            b.push(Block::Table {
                headers: vec!["Section".into(), "Taille brute".into(), "Taille virtuelle".into(), "Entropie".into()],
                rows: bin
                    .sections
                    .iter()
                    .take(60)
                    .map(|s| {
                        let ent = format!("{:.2}", s.entropy);
                        vec![
                            Cell::mono(s.name.clone()),
                            Cell::new(format_bytes(s.raw_size)),
                            Cell::new(format_bytes(s.virtual_size)),
                            if s.entropy > 7.2 { Cell::toned(ent, Tone::Warn) } else { Cell::new(ent) },
                        ]
                    })
                    .collect(),
                widths: vec![2.0, 1.5, 1.5, 1.0],
            });
        }
        if !bin.suspicious_imports.is_empty() {
            b.push(Block::KeyValues {
                items: vec![("Fonctions sensibles".into(), bin.suspicious_imports.join(", "))],
                mono: true,
            });
        }
    }
    if let Some(sc) = &r.script_info {
        b.push(Block::Heading(2, format!("Script {}", sc.script_type)));
        b.push(Block::KeyValues {
            items: vec![
                ("Obfuscation".into(), if sc.obfuscation_detected { "Détectée".into() } else { "Non détectée".into() }),
                ("Blocs Base64".into(), sc.base64_blobs_count.to_string()),
                ("Commandes sensibles".into(), if sc.dangerous_calls.is_empty() { "Aucune".into() } else { sc.dangerous_calls.join(", ") }),
            ],
            mono: false,
        });
        if !sc.matched_lines.is_empty() {
            b.push(Block::Table {
                headers: vec!["Ligne".into(), "Commande".into(), "Contenu".into()],
                rows: sc
                    .matched_lines
                    .iter()
                    .take(60)
                    .map(|l| vec![Cell::new(l.line_number.to_string()), Cell::mono(l.pattern.clone()), Cell::mono(l.line_content.clone())])
                    .collect(),
                widths: vec![0.7, 1.8, 6.0],
            });
        }
        if !sc.base64_samples.is_empty() {
            b.push(Block::Heading(2, "Extraits Base64".into()));
            b.push(Block::Code(sc.base64_samples.join("\n")));
        }
    }
    if !r.yara_matches.is_empty() {
        b.push(Block::Heading(2, format!("Règles de détection déclenchées ({})", r.yara_matches.len())));
        b.push(Block::Table {
            headers: vec!["Gravité".into(), "Règle".into(), "Description".into(), "Motifs trouvés".into()],
            rows: r
                .yara_matches
                .iter()
                .map(|m| {
                    vec![
                        Cell::toned(severity_label(&m.severity), severity_tone(&m.severity)),
                        Cell::mono(m.rule_name.clone()),
                        Cell::new(m.description.clone()),
                        Cell::mono(m.matched_strings.join(", ")),
                    ]
                })
                .collect(),
            widths: vec![1.1, 2.2, 3.2, 2.5],
        });
    }
    if !r.ioc_list.is_empty() {
        b.push(Block::Heading(2, format!("Indicateurs bruts ({})", r.ioc_list.len())));
        b.push(Block::Table {
            headers: vec!["Gravité".into(), "Type".into(), "Valeur".into(), "Description".into()],
            rows: r
                .ioc_list
                .iter()
                .map(|i| {
                    vec![
                        Cell::toned(severity_label(&i.severity), severity_tone(&i.severity)),
                        Cell::new(i.ioc_type.clone()),
                        Cell::mono(i.value.clone()),
                        Cell::new(i.description.clone()),
                    ]
                })
                .collect(),
            widths: vec![1.1, 1.6, 2.6, 3.7],
        });
    }

    if let Some(ai) = &r.ai_verdict {
        b.push(Block::Heading(2, "Analyse IA locale".into()));
        b.push(Block::Para(ai.clone()));
    }

    // ── Méthode ──
    b.push(Block::Heading(1, "Méthode et limites".into()));
    if !a.method.is_empty() {
        b.push(Block::Para(a.method.clone()));
    }
    b.push(Block::Note(
        "Les pourcentages sont des estimations calibrées et justifiées (voir « Calcul du pourcentage » de chaque détection), \
         pas une certitude. Un fichier jugé sain peut rester dangereux ; en cas de doute, n'exécutez pas le fichier."
            .into(),
    ));

    Doc {
        app: "FileScanner".into(),
        title: format!("Rapport d'analyse — {}", r.file_name),
        subtitle: format!("Verdict {vlabel} · menace réelle {p} %"),
        generated_at: chrono::Utc::now().format("%d/%m/%Y %H:%M UTC").to_string(),
        blocks: b,
    }
}

/// Rend le rapport dans le format demandé (json, md, txt, html, pdf).
pub fn render(r: &ScanResult, format: &str) -> Result<Vec<u8>, ScanError> {
    Ok(match format {
        "json" => serde_json::to_vec_pretty(r).map_err(|e| ScanError::ExportError(e.to_string()))?,
        "md" => report::markdown::render(&build(r)).into_bytes(),
        "txt" => report::text::render(&build(r)).into_bytes(),
        "html" => report::html::render(&build(r)).into_bytes(),
        "pdf" => report::pdf::render(&build(r)),
        _ => return Err(ScanError::ExportError(format!("Format inconnu : {format}"))),
    })
}

pub fn export(result: &ScanResult, format: &str, output_path: &str) -> Result<(), ScanError> {
    std::fs::write(output_path, render(result, format)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::types::{Hashes, IoC, YaraMatch};

    fn sample() -> ScanResult {
        let mut r = ScanResult {
            file_path: "C:/tmp/facture_été.exe".into(),
            file_name: "facture_été.exe".into(),
            file_size: 123_456,
            mime_type: "application/x-msdownload".into(),
            category: "Exécutable".into(),
            hashes: Hashes { md5: "d41d8cd98f00b204e9800998ecf8427e".into(), sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into() },
            verdict: Verdict::Unknown,
            verdict_score: 0,
            pe_info: None,
            script_info: None,
            virustotal: None,
            clamav: None,
            yara_matches: vec![YaraMatch { rule_name: "Mimikatz_Strings".into(), description: "Chaînes Mimikatz <script>".into(), severity: Severity::Critical, matched_strings: vec!["sekurlsa".into()] }],
            ai_verdict: None,
            ioc_list: vec![IoC { ioc_type: "Import suspect".into(), value: "WriteProcessMemory".into(), severity: Severity::High, description: String::new() }],
            scanned_at: "2026-09-28T14:05:00Z".into(),
            explanation: String::new(),
            intel: vec![],
            detections: vec![],
            assessment: Default::default(),
        };
        crate::assessment::assess(&mut r, false);
        r.explanation = crate::explain::explain(&r);
        r
    }

    /// Tous les formats se rendent ; le PDF est lisible et garde les accents (é = 0xE9 en WinAnsi).
    #[test]
    fn tous_les_formats_et_pdf_valide() {
        let r = sample();
        for f in ["json", "md", "txt", "html"] {
            let out = String::from_utf8(render(&r, f).unwrap()).unwrap();
            // Markdown échappe le « _ » du nom ; on vérifie la partie stable du nom.
            assert!(out.contains("été.exe"), "{f}");
        }
        let html = String::from_utf8(render(&r, "html").unwrap()).unwrap();
        assert!(!html.contains("<script>"), "chaîne du fichier non échappée");
        assert!(render(&r, "exe").is_err());

        let pdf = render(&r, "pdf").unwrap();
        let doc = lopdf::Document::load_mem(&pdf).unwrap();
        assert!(!doc.get_pages().is_empty());
        // pdf.rs encode chaque octet non-ASCII en octal : « é » (0xE9) devient « \351 ».
        let all: Vec<u8> = doc.get_pages().values().flat_map(|p| doc.get_page_content(*p)).collect();
        let text = String::from_utf8_lossy(&all);
        assert!(
            text.contains(r"facture_\351t\351.exe"),
            "nom de fichier accentué introuvable dans le PDF (attendu échappé en octal)"
        );
    }
}
