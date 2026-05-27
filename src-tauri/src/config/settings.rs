use keyring::Entry;

use crate::error::ScanError;
use crate::report::types::AppSettings;

const SERVICE_NAME: &str = "com.filescanner.app";
const VT_KEY_ACCOUNT: &str = "virustotal_api_key";
const AI_ENABLED_ACCOUNT: &str = "ai_enabled";
const CLAMAV_PATH_ACCOUNT: &str = "clamav_db_path";

pub fn load() -> Result<AppSettings, ScanError> {
    let vt_api_key = read_credential(VT_KEY_ACCOUNT).unwrap_or_default();
    let ai_enabled = read_credential(AI_ENABLED_ACCOUNT)
        .map(|v| v == "true")
        .unwrap_or(false);
    let clamav_db_path = read_credential(CLAMAV_PATH_ACCOUNT).unwrap_or_default();

    Ok(AppSettings {
        vt_api_key,
        ai_enabled,
        clamav_db_path,
    })
}

pub fn save(settings: &AppSettings) -> Result<(), ScanError> {
    write_credential(VT_KEY_ACCOUNT, &settings.vt_api_key)?;
    write_credential(AI_ENABLED_ACCOUNT, if settings.ai_enabled { "true" } else { "false" })?;
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
        let _ = entry.delete_credential();
    } else {
        entry.set_password(value)?;
    }
    Ok(())
}
