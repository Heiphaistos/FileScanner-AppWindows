use crate::error::ScanError;
use crate::report::types::{ScanResult, Verdict};

/// M2 — Échappe les caractères HTML spéciaux pour prévenir toute injection XSS
/// dans les rapports HTML générés.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

pub fn export_json(result: &ScanResult, output_path: &str) -> Result<(), ScanError> {
    let json = serde_json::to_string_pretty(result)
        .map_err(|e| ScanError::ExportError(e.to_string()))?;
    std::fs::write(output_path, json)?;
    Ok(())
}

pub fn export_txt(result: &ScanResult, output_path: &str) -> Result<(), ScanError> {
    let mut out = String::new();
    out.push_str("=== FILESCANNER — RAPPORT D'ANALYSE ===\n\n");
    out.push_str(&format!("Fichier    : {}\n", result.file_name));
    out.push_str(&format!("Chemin     : {}\n", result.file_path));
    out.push_str(&format!("Taille     : {} octets\n", result.file_size));
    out.push_str(&format!("MIME réel  : {}\n", result.mime_type));
    out.push_str(&format!("Scanné le  : {}\n\n", result.scanned_at));

    out.push_str("--- HASHES ---\n");
    out.push_str(&format!("MD5    : {}\n", result.hashes.md5));
    out.push_str(&format!("SHA256 : {}\n\n", result.hashes.sha256));

    out.push_str("--- VERDICT ---\n");
    out.push_str(&format!(
        "Résultat : {} (score : {}/100)\n\n",
        result.verdict, result.verdict_score
    ));

    if let Some(vt) = &result.virustotal {
        out.push_str("--- VIRUSTOTAL ---\n");
        out.push_str(&format!(
            "Détections : {}/{}\n",
            vt.positives, vt.total
        ));
        out.push_str(&format!("Date scan  : {}\n", vt.scan_date));
        out.push_str(&format!("Lien       : {}\n\n", vt.permalink));
    }

    if !result.yara_matches.is_empty() {
        out.push_str("--- RÈGLES YARA DÉCLENCHÉES ---\n");
        for m in &result.yara_matches {
            out.push_str(&format!("[{:?}] {} — {}\n", m.severity, m.rule_name, m.description));
        }
        out.push('\n');
    }

    if !result.ioc_list.is_empty() {
        out.push_str("--- INDICATEURS DE COMPROMISSION (IoC) ---\n");
        for ioc in &result.ioc_list {
            out.push_str(&format!(
                "[{:?}] {} : {} — {}\n",
                ioc.severity, ioc.ioc_type, ioc.value, ioc.description
            ));
        }
        out.push('\n');
    }

    if let Some(ai) = &result.ai_verdict {
        out.push_str("--- ANALYSE IA LOCALE ---\n");
        out.push_str(ai);
        out.push('\n');
    }

    std::fs::write(output_path, out)?;
    Ok(())
}

pub fn export_md(result: &ScanResult, output_path: &str) -> Result<(), ScanError> {
    let verdict_emoji = match result.verdict {
        Verdict::Safe => "✅",
        Verdict::Suspicious => "⚠️",
        Verdict::Malicious => "🚨",
        Verdict::Unknown => "❓",
    };

    let mut out = String::new();
    out.push_str(&format!("# FileScanner — Rapport d'analyse\n\n"));
    out.push_str(&format!(
        "## {} Verdict : {} ({}/100)\n\n",
        verdict_emoji, result.verdict, result.verdict_score
    ));
    out.push_str("## Informations fichier\n\n");
    out.push_str(&format!("| Champ | Valeur |\n|---|---|\n"));
    out.push_str(&format!("| Nom | `{}` |\n", result.file_name));
    out.push_str(&format!("| Taille | {} octets |\n", result.file_size));
    out.push_str(&format!("| MIME | `{}` |\n", result.mime_type));
    out.push_str(&format!("| MD5 | `{}` |\n", result.hashes.md5));
    out.push_str(&format!("| SHA256 | `{}` |\n", result.hashes.sha256));
    out.push_str(&format!("| Scanné le | {} |\n\n", result.scanned_at));

    if let Some(vt) = &result.virustotal {
        out.push_str("## VirusTotal\n\n");
        out.push_str(&format!(
            "- **Détections** : {}/{}\n",
            vt.positives, vt.total
        ));
        out.push_str(&format!("- **Date** : {}\n", vt.scan_date));
        out.push_str(&format!("- [Voir rapport]({})\n\n", vt.permalink));
    }

    if !result.yara_matches.is_empty() {
        out.push_str("## Règles déclenchées\n\n");
        for m in &result.yara_matches {
            out.push_str(&format!(
                "- **[{:?}]** `{}` — {}\n",
                m.severity, m.rule_name, m.description
            ));
        }
        out.push('\n');
    }

    if !result.ioc_list.is_empty() {
        out.push_str("## Indicateurs de compromission\n\n");
        out.push_str("| Type | Valeur | Sévérité | Description |\n|---|---|---|---|\n");
        for ioc in &result.ioc_list {
            out.push_str(&format!(
                "| {} | `{}` | {:?} | {} |\n",
                ioc.ioc_type, ioc.value, ioc.severity, ioc.description
            ));
        }
        out.push('\n');
    }

    if let Some(ai) = &result.ai_verdict {
        out.push_str("## Analyse IA locale\n\n");
        out.push_str(&format!("> {}\n\n", ai));
    }

    std::fs::write(output_path, out)?;
    Ok(())
}

pub fn export_html(result: &ScanResult, output_path: &str) -> Result<(), ScanError> {
    let verdict_color = match result.verdict {
        Verdict::Safe => "#22c55e",
        Verdict::Suspicious => "#f97316",
        Verdict::Malicious => "#ef4444",
        Verdict::Unknown => "#6b7280",
    };

    let vt_block = if let Some(vt) = &result.virustotal {
        format!(
            r#"<div class="section"><h2>VirusTotal</h2>
            <p><strong>Détections :</strong> {}/{}</p>
            <p><strong>Date :</strong> {}</p>
            <p><a href="{}" target="_blank">Voir le rapport</a></p></div>"#,
            vt.positives, vt.total, vt.scan_date, vt.permalink
        )
    } else {
        String::new()
    };

    let yara_block = if !result.yara_matches.is_empty() {
        let rows: String = result
            .yara_matches
            .iter()
            .map(|m| {
                format!(
                    "<tr><td>{:?}</td><td>{}</td><td>{}</td></tr>",
                    m.severity,
                    html_escape(&m.rule_name),
                    html_escape(&m.description)
                )
            })
            .collect();
        format!(
            r#"<div class="section"><h2>Règles YARA déclenchées</h2>
            <table><tr><th>Sévérité</th><th>Règle</th><th>Description</th></tr>{}</table></div>"#,
            rows
        )
    } else {
        String::new()
    };

    let ioc_block = if !result.ioc_list.is_empty() {
        let rows: String = result
            .ioc_list
            .iter()
            .map(|ioc| {
                format!(
                    "<tr><td>{}</td><td><code>{}</code></td><td>{:?}</td><td>{}</td></tr>",
                    html_escape(&ioc.ioc_type),
                    html_escape(&ioc.value),
                    ioc.severity,
                    html_escape(&ioc.description)
                )
            })
            .collect();
        format!(
            r#"<div class="section"><h2>Indicateurs de compromission</h2>
            <table><tr><th>Type</th><th>Valeur</th><th>Sévérité</th><th>Description</th></tr>{}</table></div>"#,
            rows
        )
    } else {
        String::new()
    };

    let ai_block = if let Some(ai) = &result.ai_verdict {
        format!(
            r#"<div class="section"><h2>Analyse IA locale</h2><p class="ai-verdict">{}</p></div>"#,
            html_escape(ai)
        )
    } else {
        String::new()
    };

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<title>FileScanner — Rapport d'analyse</title>
<style>
  body {{ font-family: 'Segoe UI', sans-serif; background: #0f172a; color: #e2e8f0; margin: 0; padding: 2rem; }}
  h1 {{ color: #f8fafc; }}
  h2 {{ color: #94a3b8; font-size: 1rem; text-transform: uppercase; letter-spacing: 0.1em; margin-top: 2rem; }}
  .verdict {{ font-size: 2rem; font-weight: bold; color: {}; padding: 1rem 2rem; border: 2px solid {}; border-radius: 8px; display: inline-block; margin: 1rem 0; }}
  .section {{ background: #1e293b; border-radius: 8px; padding: 1.5rem; margin: 1rem 0; }}
  table {{ width: 100%; border-collapse: collapse; }}
  th, td {{ text-align: left; padding: 0.5rem; border-bottom: 1px solid #334155; }}
  th {{ color: #94a3b8; }}
  code {{ background: #0f172a; padding: 0.2rem 0.4rem; border-radius: 4px; font-size: 0.85em; }}
  a {{ color: #60a5fa; }}
  .ai-verdict {{ background: #1e293b; border-left: 3px solid #60a5fa; padding: 1rem; }}
  .hash {{ font-family: monospace; font-size: 0.8em; color: #94a3b8; }}
</style>
</head>
<body>
<h1>FileScanner — Rapport d'analyse</h1>
<div class="verdict">{} — {}/100</div>
<div class="section">
  <h2>Informations fichier</h2>
  <p><strong>Nom :</strong> {}</p>
  <p><strong>Taille :</strong> {} octets</p>
  <p><strong>MIME réel :</strong> {}</p>
  <p><strong>MD5 :</strong> <span class="hash">{}</span></p>
  <p><strong>SHA256 :</strong> <span class="hash">{}</span></p>
  <p><strong>Scanné le :</strong> {}</p>
</div>
{}{}{}{}
</body>
</html>"#,
        verdict_color,
        verdict_color,
        result.verdict,
        result.verdict_score,
        html_escape(&result.file_name),
        result.file_size,
        html_escape(&result.mime_type),
        html_escape(&result.hashes.md5),
        html_escape(&result.hashes.sha256),
        html_escape(&result.scanned_at),
        vt_block,
        yara_block,
        ioc_block,
        ai_block
    );

    std::fs::write(output_path, html)?;
    Ok(())
}

pub fn export_pdf(result: &ScanResult, output_path: &str) -> Result<(), ScanError> {
    use printpdf::*;

    let (doc, page1, layer1) =
        PdfDocument::new("FileScanner Rapport", Mm(210.0), Mm(297.0), "Couche 1");
    let layer = doc.get_page(page1).get_layer(layer1);
    let font = doc
        .add_builtin_font(BuiltinFont::Helvetica)
        .map_err(|e| ScanError::PdfError(e.to_string()))?;
    let font_bold = doc
        .add_builtin_font(BuiltinFont::HelveticaBold)
        .map_err(|e| ScanError::PdfError(e.to_string()))?;

    // printpdf 0.6 : Mm(f32), use_text(text, font_size: f32, x: Mm, y: Mm, font)
    let mut y = 270.0_f32;
    let left = 20.0_f32;

    layer.use_text("FileScanner - Rapport d'analyse", 16.0_f32, Mm(left), Mm(y), &font_bold);
    y -= 10.0;
    layer.use_text(
        format!("Verdict : {} ({}/100)", result.verdict, result.verdict_score),
        12.0_f32, Mm(left), Mm(y), &font_bold,
    );
    y -= 8.0;
    layer.use_text(
        format!("Fichier : {}  |  {} octets", result.file_name, result.file_size),
        10.0_f32, Mm(left), Mm(y), &font,
    );
    y -= 6.0;
    layer.use_text(
        format!("MIME : {}  |  Scanne le : {}", result.mime_type, result.scanned_at),
        10.0_f32, Mm(left), Mm(y), &font,
    );
    y -= 8.0;
    layer.use_text(format!("MD5    : {}", result.hashes.md5), 9.0_f32, Mm(left), Mm(y), &font);
    y -= 6.0;
    layer.use_text(format!("SHA256 : {}", result.hashes.sha256), 9.0_f32, Mm(left), Mm(y), &font);
    y -= 10.0;

    if let Some(vt) = &result.virustotal {
        layer.use_text("VirusTotal", 12.0_f32, Mm(left), Mm(y), &font_bold);
        y -= 6.0;
        layer.use_text(
            format!("Detections : {}/{}  |  {}", vt.positives, vt.total, vt.scan_date),
            10.0_f32, Mm(left), Mm(y), &font,
        );
        y -= 10.0;
    }

    if !result.yara_matches.is_empty() {
        layer.use_text("Regles declenchees", 12.0_f32, Mm(left), Mm(y), &font_bold);
        y -= 6.0;
        for m in &result.yara_matches {
            if y < 20.0 { break; }
            layer.use_text(
                format!("[{:?}] {} - {}", m.severity, m.rule_name, m.description),
                9.0_f32, Mm(left), Mm(y), &font,
            );
            y -= 5.0;
        }
        y -= 5.0;
    }

    if !result.ioc_list.is_empty() && y > 20.0 {
        layer.use_text("Indicateurs de compromission", 12.0_f32, Mm(left), Mm(y), &font_bold);
        y -= 6.0;
        for ioc in &result.ioc_list {
            if y < 20.0 { break; }
            layer.use_text(
                format!("[{:?}] {} : {}", ioc.severity, ioc.ioc_type, ioc.value),
                9.0_f32, Mm(left), Mm(y), &font,
            );
            y -= 5.0;
        }
    }

    let bytes = doc
        .save_to_bytes()
        .map_err(|e| ScanError::PdfError(e.to_string()))?;

    std::fs::write(output_path, bytes)?;
    Ok(())
}

pub fn export(result: &ScanResult, format: &str, output_path: &str) -> Result<(), ScanError> {
    match format {
        "json" => export_json(result, output_path),
        "txt" => export_txt(result, output_path),
        "md" => export_md(result, output_path),
        "html" => export_html(result, output_path),
        "pdf" => export_pdf(result, output_path),
        _ => Err(ScanError::ExportError(format!(
            "Format inconnu : {}",
            format
        ))),
    }
}
