//! assessment.rs — Probabilité de menace réelle vs faux positif, par détection et globale.
//!
//! Méthode (transparente, chaque ajustement est conservé et affiché) :
//! 1. Chaque signal part d'une probabilité de base issue de `knowledge` : à quel point
//!    ce signal SEUL est-il spécifique aux malwares ?
//! 2. Le contexte réel du fichier l'ajuste : réputation en ligne (antivirus, bases de
//!    fichiers légitimes), signature d'éditeur, co-occurrences (téléchargement +
//!    exécution), commande présente seulement en commentaire, document qui ne fait
//!    que *citer* un nom de malware, installeur compressé…
//! 3. La probabilité globale combine les familles de signaux indépendantes
//!    (1 − Π(1 − pᵢ)) ; un signal fort (ClamAV, base de hash, MalwareBazaar) fixe 99 %.
//!
//! Ce n'est pas une statistique mesurée sur un corpus : c'est une estimation calibrée
//! et justifiée, ligne par ligne, pour que l'utilisateur puisse la vérifier.

use std::collections::BTreeMap;

use crate::api::intel::{IntelResult, IntelStatus, VtResult};
use crate::knowledge::{self, Kb};
use crate::report::types::{Assessment, Detection, Factor, ScanResult, Severity, SigStatus, Verdict};

/// Contexte global du fichier, calculé une fois.
struct Ctx {
    known_good: Option<String>,
    vt_clean: Option<String>,
    vt_widely_seen: bool,
    signed_verified: Option<String>,
    /// Signature intégrée intacte, certificat non reconnu (auto-signé, racine absente).
    signed_untrusted: Option<String>,
    signed_unverified: bool,
    av_confirmed: Option<String>,
    is_document: bool,
    is_installer: bool,
    script_download: bool,
    script_exec: bool,
    /// Téléchargement ou exécution « en mémoire » présent (hors commentaires).
    script_memory: bool,
    script_obfuscated: bool,
    injection_trio: bool,
}

const DOWNLOAD_CALLS: &[&str] = &[
    "downloadstring", "downloadfile", "webclient", "invoke-webrequest", "curl ", "wget ", "bitsadmin", "certutil",
];
const EXEC_CALLS: &[&str] = &[
    "invoke-expression", "iex", "start-process", "eval(", "exec(", "bash -i", "os.system", "shell_exec", "mshta",
    "regsvr32", "rundll32", "reflection.assembly",
];
/// Exécution EN MÉMOIRE (sans fichier) : typique des malwares, rare chez un installeur.
const MEMORY_EXEC: &[&str] = &["invoke-expression", "iex", "eval(", "reflection.assembly", "mshta", "regsvr32"];
const MEMORY_DOWNLOAD: &[&str] = &["downloadstring"];

fn build_ctx(r: &ScanResult, vt: Option<&VtResult>, intel: &[IntelResult], is_installer: bool) -> Ctx {
    let known_good = intel
        .iter()
        .find(|s| s.status == IntelStatus::KnownGood)
        .map(|s| format!("{} : {}", s.source, s.summary));
    let malicious_sources: Vec<&str> = intel
        .iter()
        .filter(|s| s.status == IntelStatus::Malicious)
        .map(|s| s.source.as_str())
        .collect();

    let (vt_clean, vt_widely_seen, vt_signed) = match vt {
        Some(v) => {
            let clean = (v.positives == 0 && v.suspicious == 0 && v.total >= 50)
                .then(|| format!("0 détection sur {} antivirus (VirusTotal)", v.total));
            let seen = v.times_submitted >= 10;
            let signed = v.signature.as_ref().and_then(|s| {
                (s.verified.eq_ignore_ascii_case("signed")).then(|| {
                    let who = s.signers.split(';').next().unwrap_or("").trim();
                    if who.is_empty() { "éditeur vérifié".to_string() } else { who.to_string() }
                })
            });
            (clean, seen, signed)
        }
        None => (None, false, None),
    };

    // Commandes réellement actives : une commande citée seulement en commentaire ne compte pas.
    let calls: Vec<String> = r
        .script_info
        .as_ref()
        .map(|s| {
            s.dangerous_calls
                .iter()
                .filter(|c| {
                    let lines: Vec<_> = s.matched_lines.iter().filter(|l| &l.pattern == *c).collect();
                    lines.is_empty() || !lines.iter().all(|l| is_comment(&l.line_content))
                })
                .map(|c| c.to_ascii_lowercase())
                .collect()
        })
        .unwrap_or_default();
    let has_call = |list: &[&str]| calls.iter().any(|c| list.contains(&c.as_str()));

    let imports: Vec<String> = r
        .pe_info
        .as_ref()
        .map(|b| b.suspicious_imports.iter().map(|i| i.to_ascii_lowercase()).collect())
        .unwrap_or_default();
    let imp = |k: &str| imports.iter().any(|i| i.contains(k));

    let sig = r.pe_info.as_ref().map(|b| &b.signature);

    let is_document = matches!(r.category.as_str(), "Document" | "Autre")
        || r.mime_type.starts_with("text/plain")
        || r.mime_type.starts_with("image/");

    Ctx {
        known_good,
        vt_clean,
        vt_widely_seen,
        // Windows qui valide la signature localement prime sur l'avis de VirusTotal.
        signed_verified: sig
            .filter(|s| s.trusted())
            .map(|s| if s.status == SigStatus::Catalog { format!("{}, catalogue Windows", s.signer) } else { s.signer.clone() })
            .or(vt_signed),
        signed_untrusted: sig.filter(|s| s.status == SigStatus::Untrusted).map(|s| s.label.clone()),
        signed_unverified: sig.is_some_and(|s| s.status == SigStatus::Unverified),
        av_confirmed: (!malicious_sources.is_empty()).then(|| malicious_sources.join(", ")),
        is_document,
        is_installer,
        script_download: has_call(DOWNLOAD_CALLS),
        script_exec: has_call(EXEC_CALLS),
        script_memory: has_call(MEMORY_EXEC) || has_call(MEMORY_DOWNLOAD),
        script_obfuscated: r.script_info.as_ref().is_some_and(|s| s.obfuscation_detected),
        injection_trio: imp("virtualallocex") && imp("writeprocessmemory") && imp("createremotethread"),
    }
}

/// Signal brut avant contextualisation.
struct Signal {
    id: String,
    group: &'static str,
    source: &'static str,
    title: String,
    value: String,
    severity: Severity,
    kb: Kb,
    evidence: Vec<String>,
    /// Probabilité imposée (signal fort indiscutable) — ignore base et facteurs.
    hard: Option<u8>,
    /// Facteurs propres au signal (en plus des facteurs de contexte).
    own_factors: Vec<Factor>,
    /// Le signal est une mention textuelle (nom de malware) plutôt qu'un comportement.
    mention: bool,
    kind: Kind,
}

#[derive(PartialEq, Clone, Copy)]
enum Kind {
    Yara,
    Script,
    Import,
    Structure,
    Intel,
}

fn factor(label: impl Into<String>, delta: i16) -> Factor {
    Factor { label: label.into(), delta }
}

fn is_comment(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with('#')
        || t.starts_with("//")
        || t.starts_with("::")
        || t.starts_with('\'')
        || t.starts_with("<#")
        || t.starts_with("/*")
        || t.starts_with('*')
        || t.to_ascii_lowercase().starts_with("rem ")
}

/// Règles YARA qui détectent un NOM (famille, outil) plutôt qu'un comportement.
pub(crate) fn is_mention_rule(rule: &str) -> bool {
    matches!(
        rule,
        "Ransomware_Modern_Families"
            | "Ransomware_Extensions"
            | "Ransomware_Strings"
            | "Ransomware_Payment"
            | "Mimikatz_Strings"
            | "CobaltStrike_Beacon"
            | "Common_RAT_Strings"
            | "RAT_Families_2"
            | "APT_Implant_Families"
            | "C2_PostEx_Frameworks"
            | "Stealer_Modern_Families"
            | "Stealer_Families_3"
            | "Malware_Loader_Families"
            | "Loader_Families_2"
            | "Wiper_Families"
            | "Impacket_Lateral_Movement"
            | "AD_Attack_Tools"
            | "GPU_Miner_Binaries"
            | "CryptoMiner_Strings"
            | "UAC_Bypass_Techniques"
    )
}

fn collect_signals(r: &ScanResult, intel: &[IntelResult], vt: Option<&VtResult>) -> Vec<Signal> {
    let mut out = Vec::new();

    // Signaux forts locaux.
    for ioc in &r.ioc_list {
        let (hard_title, what) = match ioc.ioc_type.as_str() {
            "ClamAV" => ("Signature antivirus ClamAV", "L'antivirus ClamAV reconnaît ce fichier exact comme un malware répertorié."),
            "HashReputation" => ("Empreinte de malware connue", "L'empreinte SHA-256 de ce fichier figure dans une base de malwares confirmés."),
            _ => continue,
        };
        out.push(Signal {
            id: format!("hard:{}", ioc.ioc_type),
            group: "reputation",
            source: "Base de signatures",
            title: hard_title.to_string(),
            value: ioc.value.clone(),
            severity: Severity::Critical,
            kb: Kb {
                what,
                why_bad: "Correspondance exacte avec un échantillon malveillant déjà analysé par des chercheurs.",
                why_ok: "Quasiment impossible : une empreinte identique signifie un fichier identique (seule une erreur de classement dans la base l'expliquerait).",
                base: 99,
            },
            evidence: vec![ioc.description.clone()],
            hard: Some(99),
            own_factors: vec![],
            mention: false,
            kind: Kind::Intel,
        });
    }

    // Règles YARA.
    for m in &r.yara_matches {
        out.push(Signal {
            id: format!("yara:{}", m.rule_name),
            group: "yara",
            source: "Règle de détection",
            title: m.description.clone(),
            value: m.rule_name.clone(),
            severity: m.severity.clone(),
            kb: knowledge::yara_rule(&m.rule_name, &m.matched_strings),
            evidence: m.matched_strings.iter().map(|s| format!("Motif trouvé : {s}")).collect(),
            hard: None,
            own_factors: vec![],
            mention: is_mention_rule(&m.rule_name),
            kind: Kind::Yara,
        });
    }

    // Indicateurs des analyseurs spécialisés.
    for ioc in &r.ioc_list {
        let (group, source, kind, kb) = match ioc.ioc_type.as_str() {
            "ClamAV" | "HashReputation" => continue,
            "Appel dangereux" => ("script", "Commande de script", Kind::Script, knowledge::script_call(&ioc.value)),
            "Import suspect" => ("imports", "Fonction importée", Kind::Import, knowledge::import(&ioc.value)),
            "Obfuscation" => ("script", "Obfuscation", Kind::Script, knowledge::other(&ioc.ioc_type, &ioc.value)),
            "Entropie" | "Packing" | "Packer" => ("packing", "Structure du binaire", Kind::Structure, knowledge::other(&ioc.ioc_type, &ioc.value)),
            "Signature" | "ELF" => ("signature", "Structure du binaire", Kind::Structure, knowledge::other(&ioc.ioc_type, &ioc.value)),
            _ => ("other", "Indicateur", Kind::Structure, knowledge::other(&ioc.ioc_type, &ioc.value)),
        };

        let mut evidence = Vec::new();
        let mut own = Vec::new();
        if kind == Kind::Script && ioc.ioc_type == "Appel dangereux" {
            if let Some(si) = &r.script_info {
                let lines: Vec<_> = si.matched_lines.iter().filter(|l| l.pattern == ioc.value).collect();
                for l in &lines {
                    evidence.push(format!("Ligne {} : {}", l.line_number, l.line_content));
                }
                if !lines.is_empty() && lines.iter().all(|l| is_comment(&l.line_content)) {
                    own.push(factor("n'apparaît que dans des commentaires (jamais exécuté)", -30));
                }
            }
        }
        let title = match ioc.ioc_type.as_str() {
            "Appel dangereux" => format!("Commande « {} »", ioc.value),
            "Import suspect" => format!("Fonction système « {} »", ioc.value),
            _ => ioc.description.clone(),
        };
        out.push(Signal {
            id: format!("{}:{}", ioc.ioc_type, ioc.value),
            group,
            source,
            title,
            value: ioc.value.clone(),
            severity: ioc.severity.clone(),
            kb,
            evidence,
            hard: None,
            own_factors: own,
            mention: false,
            kind,
        });
    }

    // Réputation en ligne : chaque source qui signale le fichier est un signal.
    for s in intel {
        let (conf, why_ok): (u8, &'static str) = match (s.source.as_str(), s.status) {
            (_, IntelStatus::Malicious) if s.source.starts_with("MalwareBazaar") => (98, "Quasi nul : l'échantillon exact a été confirmé malveillant par des analystes."),
            (_, IntelStatus::Malicious) if s.source.starts_with("ThreatFox") => (95, "Très faible : l'empreinte est liée à une campagne malveillante documentée."),
            ("VirusTotal", IntelStatus::Malicious) | ("MetaDefender (OPSWAT)", IntelStatus::Malicious) => {
                let d = s.detections.unwrap_or(0);
                if d >= 10 { (97, "Très faible : un grand nombre d'antivirus indépendants s'accordent.") }
                else { (82, "Faible : plusieurs antivirus indépendants s'accordent, mais certains réutilisent le même moteur.") }
            }
            (_, IntelStatus::Malicious) if s.source.starts_with("Kaspersky") => (90, "Faible : classement explicite par Kaspersky."),
            (_, IntelStatus::Malicious) if s.source.starts_with("Hybrid") => (85, "Faible : comportement malveillant observé en exécution réelle."),
            (_, IntelStatus::Malicious) if s.source.starts_with("Team Cymru") => (88, "Faible : l'empreinte est détectée par une part importante des antivirus."),
            (_, IntelStatus::Malicious) => (72, "Possible : une source communautaire peut se tromper ou citer un fichier légitime détourné."),
            ("VirusTotal", IntelStatus::Suspicious) | ("MetaDefender (OPSWAT)", IntelStatus::Suspicious) => (
                28,
                "Élevé : 1 ou 2 moteurs sur des dizaines, c'est la signature typique d'un faux positif d'heuristique (souvent des moteurs d'IA ou des noms génériques comme « Generic », « ML », « Heur »).",
            ),
            (_, IntelStatus::Suspicious) => (40, "Réel : signal partiel ou règle générique (packer, installeur…)."),
            _ => continue,
        };
        out.push(Signal {
            id: format!("intel:{}", s.source),
            group: "reputation",
            source: "Réputation en ligne",
            title: format!("{} : {}", s.source, s.summary),
            value: s.threat_names.first().cloned().unwrap_or_default(),
            severity: if conf >= 80 { Severity::Critical } else if conf >= 40 { Severity::High } else { Severity::Medium },
            kb: Kb {
                what: "Base de réputation externe interrogée avec l'empreinte du fichier (le fichier lui-même n'est pas envoyé).",
                why_bad: "La source a déjà vu ce fichier exact et le classe comme dangereux.",
                why_ok,
                base: conf,
            },
            evidence: s
                .threat_names
                .iter()
                .take(6)
                .map(|t| format!("Détection : {t}"))
                .chain(s.details.iter().take(3).cloned())
                .collect(),
            hard: None,
            own_factors: vec![],
            mention: false,
            kind: Kind::Intel,
        });
    }
    let _ = vt;
    out
}

/// Facteurs de contexte applicables à un signal.
fn context_factors(sig: &Signal, c: &Ctx) -> Vec<Factor> {
    let mut f = Vec::new();
    let local = sig.kind != Kind::Intel;
    let v = sig.value.to_ascii_lowercase();

    if local {
        if let Some(k) = &c.known_good {
            f.push(factor(format!("fichier référencé comme LÉGITIME ({k})"), -45));
        }
        if let Some(clean) = &c.vt_clean {
            f.push(factor(clean.clone(), -25));
            if c.vt_widely_seen {
                f.push(factor("fichier déjà soumis de nombreuses fois sans jamais être détecté", -8));
            }
        }
        if let Some(who) = &c.signed_verified {
            f.push(factor(format!("signé par un éditeur vérifié ({who})"), -20));
        } else if let Some(who) = c.signed_untrusted.as_ref().filter(|_| matches!(sig.kind, Kind::Import | Kind::Structure | Kind::Yara)) {
            // N'importe qui peut créer un certificat : moins qu'une signature reconnue, mais le
            // fichier n'a pas été modifié depuis sa signature et son auteur est identifiable.
            f.push(factor(format!("{who} : fichier intact depuis sa signature"), -12));
        } else if c.signed_unverified && matches!(sig.kind, Kind::Import | Kind::Structure | Kind::Yara) {
            f.push(factor("contient une signature numérique d'éditeur (non vérifiée ici)", -8));
        }
        if let Some(av) = &c.av_confirmed {
            f.push(factor(format!("confirmé malveillant par des sources externes ({av})"), 25));
        }
    }

    match sig.kind {
        Kind::Yara if sig.mention && c.is_document => {
            f.push(factor("le fichier est un document : il peut simplement CITER ce nom (article, rapport, cours)", -25));
        }
        Kind::Script => {
            let is_dl = DOWNLOAD_CALLS.contains(&v.as_str());
            let is_ex = EXEC_CALLS.contains(&v.as_str());
            let comment_only = sig.own_factors.iter().any(|f| f.label.contains("commentaires"));
            if c.script_download && c.script_exec && (is_dl || is_ex) && !comment_only {
                if c.script_memory {
                    f.push(factor("téléchargement ET exécution en mémoire dans le même script (schéma d'infection « sans fichier »)", 15));
                } else {
                    f.push(factor("télécharge puis lance un programme (courant pour un installeur comme pour un dropper)", 5));
                }
            }
            if c.script_obfuscated && is_ex {
                f.push(factor("le script contient aussi du code encodé/obfusqué", 10));
            }
        }
        Kind::Import if c.injection_trio && ["virtualallocex", "writeprocessmemory", "createremotethread"].iter().any(|k| v.contains(k)) => {
            f.push(factor("les 3 fonctions de l'injection de code sont présentes ensemble", 20));
        }
        Kind::Structure if c.is_installer && matches!(sig.group, "packing" | "signature") => {
            f.push(factor("le fichier est un installeur : données compressées et liens web sont normaux", -10));
        }
        _ => {}
    }
    f
}

pub fn detection_verdict(p: u8) -> &'static str {
    match p {
        80..=100 => "Très probablement malveillant",
        55..=79 => "Probablement malveillant",
        30..=54 => "Douteux — à vérifier",
        12..=29 => "Probablement légitime (faux positif probable)",
        _ => "Légitime dans la grande majorité des cas (faux positif très probable)",
    }
}

pub fn verdict_for(p: u8) -> Verdict {
    match p {
        0..=25 => Verdict::Safe,
        26..=64 => Verdict::Suspicious,
        _ => Verdict::Malicious,
    }
}

/// Calcule détections + évaluation globale, puis fixe `verdict` et `verdict_score`.
pub fn assess(r: &mut ScanResult, is_installer: bool) {
    let intel = r.intel.clone();
    let ctx = build_ctx(r, r.virustotal.as_ref(), &intel, is_installer);
    let signals = collect_signals(r, &intel, r.virustotal.as_ref());

    let mut detections: Vec<Detection> = Vec::with_capacity(signals.len());
    let mut groups: BTreeMap<&'static str, Vec<u8>> = BTreeMap::new();
    let mut hard_hit = false;

    for sig in signals {
        let mut factors = sig.own_factors.clone();
        factors.extend(context_factors(&sig, &ctx));
        let conf = match sig.hard {
            Some(h) => {
                hard_hit = true;
                h
            }
            None => {
                let sum: i16 = factors.iter().map(|f| f.delta).sum();
                (sig.kb.base as i16 + sum).clamp(1, 99) as u8
            }
        };
        groups.entry(sig.group).or_default().push(conf);
        detections.push(Detection {
            id: sig.id,
            source: sig.source.to_string(),
            title: sig.title,
            value: sig.value,
            severity: sig.severity,
            confidence: conf,
            false_positive: 100 - conf,
            verdict: detection_verdict(conf).to_string(),
            what_it_does: sig.kb.what.to_string(),
            why_malicious: sig.kb.why_bad.to_string(),
            why_legitimate: sig.kb.why_ok.to_string(),
            base_confidence: sig.kb.base,
            factors,
            evidence: sig.evidence,
        });
    }

    // Combinaison : max de chaque famille (+ petit bonus de cumul), puis OU probabiliste.
    let mut p_clean = 1.0f64;
    for confs in groups.values() {
        let max = *confs.iter().max().unwrap_or(&0) as f64;
        let rest: f64 = confs.iter().map(|&c| c as f64).sum::<f64>() - max;
        let g = (max + (rest * 0.15).min(15.0)).min(99.0) / 100.0;
        p_clean *= 1.0 - g;
    }
    let mut p = ((1.0 - p_clean) * 100.0).round() as i32;
    if detections.is_empty() {
        p = 2;
    }
    if ctx.known_good.is_some() && ctx.av_confirmed.is_none() && !hard_hit {
        p = p.min(8);
    }
    if hard_hit {
        p = 99;
    }
    let p = p.clamp(1, 99) as u8;

    detections.sort_by(|a, b| b.confidence.cmp(&a.confidence).then(sev_rank(&b.severity).cmp(&sev_rank(&a.severity))));

    // Raisons lisibles des deux côtés.
    let mut reasons_malicious = Vec::new();
    let mut reasons_legitimate = Vec::new();
    for d in detections.iter().filter(|d| d.confidence >= 40).take(6) {
        reasons_malicious.push(format!("{} ({} %) — {}", d.title, d.confidence, d.why_malicious));
    }
    if let Some(k) = &ctx.known_good {
        reasons_legitimate.push(format!("Référencé comme fichier légitime : {k}."));
    }
    if let Some(v) = &ctx.vt_clean {
        reasons_legitimate.push(format!("{v}."));
    }
    if let Some(s) = &ctx.signed_verified {
        reasons_legitimate.push(format!("Signé numériquement par un éditeur vérifié : {s}."));
    } else if let Some(s) = &ctx.signed_untrusted {
        reasons_legitimate.push(format!("{s}."));
    }
    let weak = detections.iter().filter(|d| d.confidence < 30).count();
    if weak > 0 {
        reasons_legitimate.push(format!(
            "{weak} élément(s) détecté(s) sont des fonctions ou commandes courantes dans les logiciels légitimes (probabilité de menace < 30 % chacune) : leur présence seule ne prouve rien."
        ));
    }
    if ctx.is_installer {
        reasons_legitimate.push("Le fichier ressemble à un installeur : compression et liens de téléchargement y sont normaux.".into());
    }
    if detections.is_empty() {
        reasons_legitimate.push("Aucun indicateur de comportement malveillant n'a été trouvé.".into());
    }

    let label = match p {
        90..=100 => "Menace quasi certaine",
        65..=89 => "Menace probable",
        40..=64 => "Doute sérieux",
        26..=39 => "Doute faible",
        10..=25 => "Probablement sain",
        _ => "Sain selon toutes les analyses",
    }
    .to_string();

    let n_det = detections.len();
    let summary = if n_det == 0 {
        format!("Aucune détection. Probabilité résiduelle de menace estimée à {p} % (aucun scanner n'est parfait).")
    } else {
        format!(
            "{n_det} élément(s) détecté(s). Probabilité que le fichier soit réellement malveillant : {p} %. \
             Probabilité que les alertes soient des faux positifs : {} %.",
            100 - p
        )
    };

    r.assessment = Assessment {
        malicious_probability: p,
        false_positive_probability: if n_det == 0 { 0 } else { 100 - p },
        label,
        summary,
        reasons_malicious,
        reasons_legitimate,
        method: "Chaque détection part d'une probabilité de base (à quel point ce signal seul est propre aux malwares), \
                 ajustée par le contexte réel du fichier (réputation en ligne, bases de fichiers légitimes, signature, \
                 co-occurrences, commentaires, type de fichier). La probabilité globale combine les familles de signaux \
                 indépendantes ; une correspondance exacte dans une base de malwares la fixe à 99 %."
            .into(),
    };
    r.detections = detections;
    r.verdict_score = p;
    r.verdict = verdict_for(p);
}

fn sev_rank(s: &Severity) -> u8 {
    match s {
        Severity::Low => 0,
        Severity::Medium => 1,
        Severity::High => 2,
        Severity::Critical => 3,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::types::{Hashes, IoC, PeInfo, SignatureInfo, YaraMatch};

    fn imp(name: &str, severity: Severity) -> IoC {
        IoC { ioc_type: "Import suspect".into(), value: name.into(), severity, description: String::new() }
    }

    fn yara(rule: &str, severity: Severity) -> YaraMatch {
        YaraMatch { rule_name: rule.into(), description: rule.into(), severity, matched_strings: vec![] }
    }

    /// Exécutable de test : imports + règles donnés, signature au choix.
    fn exe(sig: SigStatus, imports: &[(&str, Severity)], rules: &[(&str, Severity)]) -> ScanResult {
        let signature = SignatureInfo::new(sig, "Heiphaistos".into());
        let mut ioc_list: Vec<IoC> = imports.iter().map(|(n, s)| imp(n, s.clone())).collect();
        if sig == SigStatus::Absent {
            ioc_list.push(IoC { ioc_type: "Signature".into(), value: "Non signé".into(), severity: Severity::Low, description: String::new() });
        }
        if sig == SigStatus::Invalid {
            ioc_list.push(IoC { ioc_type: "Signature".into(), value: "Invalide".into(), severity: Severity::High, description: String::new() });
        }
        let mut r = ScanResult {
            file_path: "C:/t/app.exe".into(),
            file_name: "app.exe".into(),
            file_size: 1,
            mime_type: "application/x-msdownload".into(),
            category: "Exécutable".into(),
            hashes: Hashes { md5: String::new(), sha256: String::new() },
            verdict: Verdict::Unknown,
            verdict_score: 0,
            pe_info: Some(PeInfo {
                is_64bit: true,
                is_signed: sig != SigStatus::Absent,
                signature,
                sections: vec![],
                imports: vec![],
                entry_point: 0,
                entropy_max: 0.0,
                suspicious_imports: imports.iter().map(|(n, _)| n.to_string()).collect(),
                is_packed: false,
            }),
            script_info: None,
            virustotal: None,
            clamav: None,
            yara_matches: rules.iter().map(|(n, s)| yara(n, s.clone())).collect(),
            ai_verdict: None,
            ioc_list,
            scanned_at: String::new(),
            explanation: String::new(),
            intel: vec![],
            detections: vec![],
            assessment: Default::default(),
        };
        assess(&mut r, false);
        r
    }

    /// Profil réel de PureRGB 0.20.0 portable (Tauri + WebView2) après correction de la règle « formbook ».
    const APP_ORDINAIRE: &[(&str, Severity)] = &[
        ("ReadProcessMemory", Severity::Medium),
        ("NtQueryInformationProcess", Severity::Low),
        ("IsDebuggerPresent", Severity::Low),
        ("OpenProcess", Severity::Low),
        ("CreateProcessW", Severity::Low),
        ("VirtualAlloc", Severity::Low),
        ("GetAsyncKeyState", Severity::Low),
        ("CryptDecrypt", Severity::Medium),
    ];
    const REGLES_ORDINAIRES: &[(&str, Severity)] =
        &[("Shellcode_Patterns", Severity::High), ("Keylogger_Strings", Severity::Medium)];

    const INJECTION: &[(&str, Severity)] = &[
        ("VirtualAllocEx", Severity::High),
        ("WriteProcessMemory", Severity::Critical),
        ("CreateRemoteThread", Severity::Critical),
    ];

    #[test]
    fn app_auto_signee_avec_imports_courants_reste_saine() {
        let r = exe(SigStatus::Untrusted, APP_ORDINAIRE, REGLES_ORDINAIRES);
        assert_eq!(r.verdict, Verdict::Safe, "p = {}", r.verdict_score);
        assert!(r.detections.iter().all(|d| d.factors.iter().any(|f| f.delta == -12)), "facteur signature intacte appliqué");
        assert!(r.assessment.reasons_legitimate.iter().any(|l| l.contains("Heiphaistos")));
    }

    #[test]
    fn la_signature_reconnue_attenue_plus_que_la_signature_non_reconnue() {
        let trusted = exe(SigStatus::Catalog, APP_ORDINAIRE, REGLES_ORDINAIRES).verdict_score;
        let untrusted = exe(SigStatus::Untrusted, APP_ORDINAIRE, REGLES_ORDINAIRES).verdict_score;
        let absent = exe(SigStatus::Absent, APP_ORDINAIRE, REGLES_ORDINAIRES).verdict_score;
        assert!(trusted < untrusted && untrusted < absent, "{trusted} < {untrusted} < {absent}");
    }

    #[test]
    fn injection_de_code_reste_suspecte_meme_auto_signee() {
        let r = exe(SigStatus::Untrusted, INJECTION, &[("Process_Injection", Severity::Critical)]);
        assert_ne!(r.verdict, Verdict::Safe, "p = {}", r.verdict_score);
    }

    #[test]
    fn signature_alteree_aggrave_le_verdict() {
        let invalid = exe(SigStatus::Invalid, APP_ORDINAIRE, REGLES_ORDINAIRES);
        let absent = exe(SigStatus::Absent, APP_ORDINAIRE, REGLES_ORDINAIRES);
        assert!(invalid.verdict_score > absent.verdict_score, "{} > {}", invalid.verdict_score, absent.verdict_score);
        assert_ne!(invalid.verdict, Verdict::Safe, "p = {}", invalid.verdict_score);
    }
}
