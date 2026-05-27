//! Stub ONNX — pluggable via feature flag `onnx`.
//! En v1.0 : heuristique basée sur le score agrégé uniquement.

use crate::report::types::{PeInfo, ScriptInfo, YaraMatch};

pub struct LocalInference;

impl LocalInference {
    pub fn new() -> Self {
        Self
    }

    /// Génère un verdict textuel basé sur les indicateurs collectés.
    /// Retourne None si tout est dans les normes.
    pub fn evaluate(
        &self,
        score: u8,
        pe_info: Option<&PeInfo>,
        _script_info: Option<&ScriptInfo>,
        yara_matches: &[YaraMatch],
    ) -> Option<String> {
        if score < 30 {
            return None;
        }

        let mut observations = Vec::new();

        if let Some(pe) = pe_info {
            if pe.entropy_max > 7.5 {
                observations.push("entropie très élevée (>7.5) détectée dans les sections PE");
            }
            if pe.is_packed {
                observations.push("packer ou chiffrement de section identifié");
            }
            if !pe.suspicious_imports.is_empty() {
                observations.push("présence d'imports système critiques associés à l'injection ou la surveillance");
            }
        }

        for m in yara_matches {
            match m.rule_name.as_str() {
                "Ransomware_Strings" => observations.push("chaînes caractéristiques de ransomware"),
                "Process_Injection" => observations.push("pattern d'injection de processus (CreateRemoteThread + VirtualAllocEx)"),
                "Mimikatz_Strings" => observations.push("outil de vol de credentials Mimikatz identifié"),
                "Keylogger_Strings" => observations.push("comportement de keylogger suspecté"),
                _ => {}
            }
        }

        if observations.is_empty() {
            return None;
        }

        Some(format!(
            "Analyse locale : {} (score de dangerosité : {}/100).",
            observations.join(", "),
            score
        ))
    }
}

impl Default for LocalInference {
    fn default() -> Self {
        Self::new()
    }
}
