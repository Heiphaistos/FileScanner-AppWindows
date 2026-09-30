use keyring::Entry;

use crate::error::ScanError;
use crate::report::types::AppSettings;

const SERVICE_NAME: &str = "com.filescanner.app";
const AI_ENABLED_ACCOUNT: &str = "ai_enabled";
const CLAMAV_PATH_ACCOUNT: &str = "clamav_db_path";
/// Absent = sources gratuites actives ; seul « false » les coupe.
const FREE_LOOKUPS_ACCOUNT: &str = "intel_free_lookups";

/// Compte du trousseau de chaque clé API, dans l'ordre de `api_keys`.
/// `virustotal_api_key` garde son nom historique.
const KEY_ACCOUNTS: [&str; 6] = [
    "virustotal_api_key",
    "metadefender_api_key",
    "hybrid_analysis_api_key",
    "opentip_api_key",
    "otx_api_key",
    "abusech_api_key",
];

/// Clés API (libellé, valeur), dans l'ordre de `KEY_ACCOUNTS`.
pub fn api_keys(s: &AppSettings) -> [(&'static str, &str); 6] {
    [
        ("VirusTotal", &s.vt_api_key),
        ("MetaDefender", &s.metadefender_api_key),
        ("Hybrid Analysis", &s.hybrid_analysis_api_key),
        ("Kaspersky OpenTIP", &s.opentip_api_key),
        ("AlienVault OTX", &s.otx_api_key),
        ("abuse.ch", &s.abusech_api_key),
    ]
}

pub fn load() -> Result<AppSettings, ScanError> {
    let key = |i: usize| read_credential(KEY_ACCOUNTS[i]).unwrap_or_default();
    Ok(AppSettings {
        vt_api_key: key(0),
        metadefender_api_key: key(1),
        hybrid_analysis_api_key: key(2),
        opentip_api_key: key(3),
        otx_api_key: key(4),
        abusech_api_key: key(5),
        intel_free_lookups: read_credential(FREE_LOOKUPS_ACCOUNT).is_none_or(|v| v != "false"),
        ai_enabled: read_credential(AI_ENABLED_ACCOUNT).is_some_and(|v| v == "true"),
        clamav_db_path: read_credential(CLAMAV_PATH_ACCOUNT).unwrap_or_default(),
    })
}

pub fn save(settings: &AppSettings) -> Result<(), ScanError> {
    for ((_, value), account) in api_keys(settings).into_iter().zip(KEY_ACCOUNTS) {
        write_credential(account, value.trim())?;
    }
    write_credential(AI_ENABLED_ACCOUNT, if settings.ai_enabled { "true" } else { "false" })?;
    write_credential(FREE_LOOKUPS_ACCOUNT, if settings.intel_free_lookups { "true" } else { "false" })?;
    write_credential(CLAMAV_PATH_ACCOUNT, &settings.clamav_db_path)?;
    Ok(())
}

fn read_credential(account: &str) -> Option<String> {
    let entry = Entry::new(SERVICE_NAME, account).ok()?;
    entry.get_password().ok()
}

fn write_credential(account: &str, value: &str) -> Result<(), ScanError> {
    let entry = Entry::new(SERVICE_NAME, account)?;
    if value.is_empty() {
        // Rien à supprimer n'est pas une erreur ; tout autre échec en est une.
        match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => {}
            Err(e) => return Err(e.into()),
        }
    } else {
        entry.set_password(value)?;
    }
    Ok(())
}
