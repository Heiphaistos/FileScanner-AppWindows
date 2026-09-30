use serde::{Deserialize, Serialize};

pub use crate::api::intel::{IntelResult, VtResult};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Verdict {
    Safe,
    Suspicious,
    Malicious,
    Unknown,
}

impl std::fmt::Display for Verdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Verdict::Safe => write!(f, "SAIN"),
            Verdict::Suspicious => write!(f, "SUSPECT"),
            Verdict::Malicious => write!(f, "MALVEILLANT"),
            Verdict::Unknown => write!(f, "INCONNU"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Low => write!(f, "FAIBLE"),
            Severity::Medium => write!(f, "MOYEN"),
            Severity::High => write!(f, "ÉLEVÉ"),
            Severity::Critical => write!(f, "CRITIQUE"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hashes {
    pub md5: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeSection {
    pub name: String,
    pub virtual_size: u64,
    pub raw_size: u64,
    pub entropy: f64,
    pub characteristics: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeInfo {
    pub is_64bit: bool,
    pub is_signed: bool,
    pub sections: Vec<PeSection>,
    pub imports: Vec<String>,
    pub entry_point: u64,
    pub entropy_max: f64,
    pub suspicious_imports: Vec<String>,
    pub is_packed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptMatchedLine {
    pub line_number: usize,
    pub pattern: String,
    pub line_content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptInfo {
    pub obfuscation_detected: bool,
    pub dangerous_calls: Vec<String>,
    pub base64_blobs_count: usize,
    pub script_type: String,
    pub matched_lines: Vec<ScriptMatchedLine>,
    pub base64_samples: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraMatch {
    pub rule_name: String,
    pub description: String,
    pub severity: Severity,
    pub matched_strings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IoC {
    pub ioc_type: String,
    pub value: String,
    pub severity: Severity,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClamavResult {
    pub malware_name: String,
    pub database: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub file_path: String,
    pub file_name: String,
    pub file_size: u64,
    pub mime_type: String,
    /// Catégorie lisible (« Exécutable », « Script », « Document »…).
    #[serde(default)]
    pub category: String,
    pub hashes: Hashes,
    pub verdict: Verdict,
    pub verdict_score: u8,
    pub pe_info: Option<PeInfo>,
    pub script_info: Option<ScriptInfo>,
    pub virustotal: Option<VtResult>,
    pub clamav: Option<ClamavResult>,
    pub yara_matches: Vec<YaraMatch>,
    pub ai_verdict: Option<String>,
    pub ioc_list: Vec<IoC>,
    pub scanned_at: String,
    /// Explication en français clair (générée par `explain`).
    #[serde(default)]
    pub explanation: String,
    /// Réputation auprès des bases en ligne (VirusTotal, MetaDefender, MalwareBazaar…).
    #[serde(default)]
    pub intel: Vec<IntelResult>,
    /// Chaque élément détecté, avec sa probabilité de menace réelle / faux positif.
    #[serde(default)]
    pub detections: Vec<Detection>,
    #[serde(default)]
    pub assessment: Assessment,
}

/// Ajustement appliqué à une probabilité, avec sa justification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Factor {
    pub label: String,
    /// Points de pourcentage ajoutés (+) ou retirés (−).
    pub delta: i16,
}

/// Un élément détecté, expliqué et chiffré.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Detection {
    pub id: String,
    /// Origine (« Commande de script », « Fonction importée », « Réputation en ligne »…).
    pub source: String,
    pub title: String,
    pub value: String,
    /// Gravité SI la menace est réelle.
    pub severity: Severity,
    /// Probabilité (%) que ce soit réellement malveillant.
    pub confidence: u8,
    /// Probabilité (%) que ce soit un faux positif (= 100 − confidence).
    pub false_positive: u8,
    pub verdict: String,
    pub what_it_does: String,
    pub why_malicious: String,
    pub why_legitimate: String,
    /// Probabilité de départ avant ajustements de contexte.
    pub base_confidence: u8,
    pub factors: Vec<Factor>,
    pub evidence: Vec<String>,
}

/// Évaluation globale du fichier.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Assessment {
    pub malicious_probability: u8,
    pub false_positive_probability: u8,
    pub label: String,
    pub summary: String,
    pub reasons_malicious: Vec<String>,
    pub reasons_legitimate: Vec<String>,
    pub method: String,
}

/// Réglages persistés dans le trousseau du système (`config::settings`).
/// Clé vide = source correspondante « non configurée ».
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AppSettings {
    pub vt_api_key: String,
    pub metadefender_api_key: String,
    pub hybrid_analysis_api_key: String,
    pub opentip_api_key: String,
    pub otx_api_key: String,
    /// Une clé pour MalwareBazaar + ThreatFox + YARAify.
    pub abusech_api_key: String,
    /// Team Cymru MHR + CIRCL hashlookup (sans clé).
    pub intel_free_lookups: bool,
    pub ai_enabled: bool,
    pub clamav_db_path: String,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            vt_api_key: String::new(),
            metadefender_api_key: String::new(),
            hybrid_analysis_api_key: String::new(),
            opentip_api_key: String::new(),
            otx_api_key: String::new(),
            abusech_api_key: String::new(),
            intel_free_lookups: true,
            ai_enabled: false,
            clamav_db_path: String::new(),
        }
    }
}
