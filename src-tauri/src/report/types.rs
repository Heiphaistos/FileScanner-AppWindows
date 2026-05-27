use serde::{Deserialize, Serialize};

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
pub struct VtResult {
    pub positives: u32,
    pub total: u32,
    pub permalink: String,
    pub scan_date: String,
    pub detection_names: Vec<String>,
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSettings {
    pub vt_api_key: String,
    pub ai_enabled: bool,
    pub clamav_db_path: String,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            vt_api_key: String::new(),
            ai_enabled: false,
            clamav_db_path: String::new(),
        }
    }
}
