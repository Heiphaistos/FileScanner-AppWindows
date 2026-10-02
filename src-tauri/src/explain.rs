//! explain.rs — Explique un résultat de scan en français clair pour l'utilisateur.
//!
//! Déterministe et hors-ligne : traduit les signaux techniques (règles YARA, IOCs,
//! verdict) en langage compréhensible — quoi, pourquoi c'est dangereux, quoi faire.
//! Conçu selon la discipline du claude-toolkit : résultat d'abord, honnête sur la
//! sévérité, orienté impact réel, actionnable — jamais de jargon non expliqué.

use crate::report::types::{ScanResult, Verdict};

/// Traduit un préfixe de règle / famille en explication grand public.
fn family_hint(rule: &str) -> Option<&'static str> {
    let r = rule.to_lowercase();
    let table: &[(&str, &str)] = &[
        ("ransomware", "un rançongiciel : il chiffre tes fichiers et exige une rançon pour les rendre"),
        ("_loader", "un « loader » : son rôle est de télécharger et installer d'autres virus"),
        ("loader_families", "un « loader » : il sert à installer d'autres logiciels malveillants"),
        ("stealer", "un voleur d'informations : il cherche à voler mots de passe, cookies et portefeuilles"),
        ("lsass", "un outil de vol de mots de passe (extraction de la mémoire Windows)"),
        ("keylogger", "un enregistreur de frappe : il capture ce que tu tapes au clavier"),
        ("rat", "un outil de prise de contrôle à distance : un attaquant pourrait piloter la machine"),
        ("c2_", "un outil de communication avec un serveur d'attaquant (contrôle à distance)"),
        (crate::txt!("mimikatz"), "un outil de vol d'identifiants Windows très connu"),
        ("cobaltstrike", "un cadre d'attaque professionnel utilisé pour prendre le contrôle d'un réseau"),
        ("miner", "un mineur de cryptomonnaie : il utilise ta machine pour miner à ton insu"),
        ("webshell", "une porte dérobée pour serveur web : elle permet d'exécuter des commandes à distance"),
        ("reverse_shell", "une porte dérobée qui ouvre l'accès de ta machine à un attaquant"),
        ("uac_bypass", "une technique pour contourner la demande d'autorisation Windows (UAC)"),
        ("amsi_bypass", "une technique pour désactiver la protection antimalware de Windows"),
        ("defender_tampering", "une tentative de désactiver Windows Defender"),
        ("packer", "un « packer » : il compresse/masque le code. Légitime parfois, mais souvent utilisé pour cacher un virus"),
        ("injection", "de l'injection de code : insérer du code malveillant dans un autre programme"),
        ("hollowing", "du « process hollowing » : masquer du code malveillant dans un programme légitime"),
        ("persistence", "un mécanisme pour se relancer à chaque démarrage (persistance)"),
        ("office_macro", "une macro Office à exécution automatique : vecteur d'infection courant par pièce jointe"),
        ("apt_", "des indices d'un groupe d'attaquants avancé (APT)"),
        ("impacket", "des outils de déplacement latéral dans un réseau"),
        ("ad_attack", "des outils d'attaque contre Active Directory (annuaire Windows d'entreprise)"),
    ];
    table.iter().find(|(k, _)| r.contains(k)).map(|(_, v)| *v)
}

/// Construit l'explication grand public d'un résultat de scan.
pub fn explain(result: &ScanResult) -> String {
    let mut out = String::new();

    // 1. Verdict d'abord (résultat en tête).
    match result.verdict {
        Verdict::Malicious => out.push_str(
            "⛔ Ce fichier est dangereux. Ne l'ouvre pas et ne l'exécute pas.\n\n"),
        Verdict::Suspicious => out.push_str(
            "⚠️ Ce fichier est suspect. Par prudence, ne l'ouvre pas sans vérification.\n\n"),
        Verdict::Safe => out.push_str(
            "✅ Aucun signe de danger détecté sur ce fichier.\n\n"),
        Verdict::Unknown => out.push_str(
            "❔ Analyse incomplète : impossible de conclure avec certitude. Reste prudent.\n\n"),
    }

    // 2. Le chiffre : probabilité de menace réelle vs fausse alerte.
    let a = &result.assessment;
    if result.detections.is_empty() {
        out.push_str(&format!(
            "Probabilité de menace réelle : {} % (risque résiduel, aucun élément suspect trouvé).\n\n",
            a.malicious_probability
        ));
    } else {
        out.push_str(&format!(
            "Probabilité de menace réelle : {} % — probabilité de fausse alerte : {} %.\n\n",
            a.malicious_probability, a.false_positive_probability
        ));
    }

    // 3. Ce qui a été détecté, traduit.
    let mut reasons: Vec<String> = Vec::new();

    if let Some(cl) = &result.clamav {
        reasons.push(format!("Identifié par l'antivirus ClamAV comme « {} ».", cl.malware_name));
    }
    for d in result.detections.iter().filter(|d| d.confidence >= 40 && d.source != "Base de signatures") {
        let hint = result
            .yara_matches
            .iter()
            .find(|m| d.id == format!("yara:{}", m.rule_name))
            .and_then(|m| family_hint(&m.rule_name));
        reasons.push(match hint {
            Some(h) => format!("Contient {h} — probabilité {} %.", d.confidence),
            None => format!("{} — probabilité {} %.", d.title, d.confidence),
        });
    }
    if let Some(vt) = &result.virustotal {
        if vt.positives > 0 && vt.positives < 3 {
            reasons.push(format!(
                "Seulement {} antivirus sur {} le signalent sur VirusTotal : c'est souvent une fausse alerte.",
                vt.positives, vt.total));
        }
    }

    reasons.dedup();
    if !reasons.is_empty() {
        out.push_str("Ce qui fait penser à une menace :\n");
        for r in reasons.iter().take(8) {
            out.push_str("• ");
            out.push_str(r);
            out.push('\n');
        }
        out.push('\n');
    }
    if !a.reasons_legitimate.is_empty() && a.malicious_probability < 90 {
        out.push_str("Ce qui fait penser à un fichier légitime (faux positif) :\n");
        for r in a.reasons_legitimate.iter().take(5) {
            out.push_str("• ");
            out.push_str(r);
            out.push('\n');
        }
    }

    // 4. Action claire.
    out.push('\n');
    match result.verdict {
        Verdict::Malicious => out.push_str(
            "À faire : supprime ce fichier, ou mets-le en quarantaine. Ne le partage pas. Si tu l'as déjà exécuté, change tes mots de passe importants et lance un scan complet de ta machine."),
        Verdict::Suspicious => out.push_str(
            "À faire : ne l'ouvre pas tant que tu n'es pas sûr de sa provenance. En cas de doute, supprime-le."),
        Verdict::Safe => out.push_str(
            "Aucune action nécessaire. Reste prudent avec les fichiers de provenance inconnue."),
        Verdict::Unknown => out.push_str(
            "Par précaution, traite ce fichier comme potentiellement risqué tant que son origine n'est pas sûre."),
    }
    out
}
