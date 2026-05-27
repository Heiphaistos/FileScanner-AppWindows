/// Moteur ClamAV — parse les bases de signatures open-source.
///
/// Formats supportés :
///   .hdb  → hash MD5  : <md5>:<size>:<nom_malware>
///   .hsb  → hash SHA1 : <sha1>:<size>:<nom_malware>
///   .msb  → hash SHA256: <sha256>:<size>:<nom_malware>
///   .cvd/.cld → archive gzip+tar contenant les fichiers ci-dessus
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::ScanError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClamavStatus {
    pub loaded: bool,
    pub md5_count: usize,
    pub sha256_count: usize,
    pub db_path: String,
    pub last_updated: Option<String>,
}

#[derive(Debug)]
pub struct ClamavMatch {
    pub malware_name: String,
    pub database: String,
}

pub struct ClamavDb {
    md5_map: HashMap<String, String>,
    sha256_map: HashMap<String, String>,
    db_path: PathBuf,
    last_updated: Option<String>,
}

impl ClamavDb {
    /// Charge les bases depuis un répertoire contenant des fichiers .hdb / .msb / .cvd
    pub fn load(db_dir: &Path) -> Result<Self, ScanError> {
        let mut db = ClamavDb {
            md5_map: HashMap::new(),
            sha256_map: HashMap::new(),
            db_path: db_dir.to_path_buf(),
            last_updated: None,
        };

        if !db_dir.exists() {
            return Ok(db);
        }

        for entry in std::fs::read_dir(db_dir)? {
            let entry = entry?;
            let path = entry.path();
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");

            match ext {
                "hdb" => db.parse_hash_file(&path, HashType::Md5)?,
                "msb" => db.parse_hash_file(&path, HashType::Sha256)?,
                "cvd" | "cld" => db.parse_cvd(&path)?,
                _ => {}
            }
        }

        db.last_updated = metadata_date(db_dir);
        Ok(db)
    }

    pub fn check_md5(&self, hash: &str) -> Option<ClamavMatch> {
        self.md5_map.get(hash).map(|name| ClamavMatch {
            malware_name: name.clone(),
            database: "ClamAV/MD5".to_string(),
        })
    }

    pub fn check_sha256(&self, hash: &str) -> Option<ClamavMatch> {
        self.sha256_map.get(hash).map(|name| ClamavMatch {
            malware_name: name.clone(),
            database: "ClamAV/SHA256".to_string(),
        })
    }

    pub fn status(&self) -> ClamavStatus {
        ClamavStatus {
            loaded: !self.md5_map.is_empty() || !self.sha256_map.is_empty(),
            md5_count: self.md5_map.len(),
            sha256_count: self.sha256_map.len(),
            db_path: self.db_path.display().to_string(),
            last_updated: self.last_updated.clone(),
        }
    }

    fn parse_hash_file(&mut self, path: &Path, hash_type: HashType) -> Result<(), ScanError> {
        let file = std::fs::File::open(path)?;
        let reader = BufReader::new(file);
        self.parse_hash_lines(reader, hash_type, &path.display().to_string())
    }

    fn parse_hash_lines<R: Read>(
        &mut self,
        reader: BufReader<R>,
        hash_type: HashType,
        source: &str,
    ) -> Result<(), ScanError> {
        for line in reader.lines() {
            let line = match line {
                Ok(l) => l,
                Err(_) => continue,
            };
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            // Format: <hash>:<size>:<name>
            let parts: Vec<&str> = line.splitn(3, ':').collect();
            if parts.len() < 3 {
                continue;
            }
            let hash = parts[0].to_lowercase();
            let name = parts[2].to_string();

            match hash_type {
                HashType::Md5 => {
                    if hash.len() == 32 {
                        self.md5_map.insert(hash, name);
                    }
                }
                HashType::Sha256 => {
                    if hash.len() == 64 {
                        self.sha256_map.insert(hash, name);
                    }
                }
            }
        }
        let _ = source; // évite warning unused
        Ok(())
    }

    fn parse_cvd(&mut self, path: &Path) -> Result<(), ScanError> {
        // M1 — Anti-bomb : refuse les fichiers CVD > 500 MB
        const MAX_CVD_SIZE: u64 = 500 * 1024 * 1024;
        let file_size = std::fs::metadata(path)?.len();
        if file_size > MAX_CVD_SIZE {
            log::warn!(
                "CVD ignoré (trop volumineux : {} Mo > 500 Mo) : {}",
                file_size / 1_048_576,
                path.display()
            );
            return Ok(());
        }

        let file = std::fs::File::open(path)?;
        let mut reader = BufReader::new(file);

        // CVD header : 512 octets texte
        let mut header = [0u8; 512];
        reader.read_exact(&mut header).map_err(ScanError::Io)?;

        // Le reste est un flux gzip+tar
        let gz = flate2::read::GzDecoder::new(reader);
        let mut archive = tar::Archive::new(gz);

        for entry in archive.entries().map_err(ScanError::Io)? {
            let mut entry = entry.map_err(ScanError::Io)?;
            let path_in_tar = entry
                .path()
                .map_err(ScanError::Io)?
                .to_string_lossy()
                .to_string();

            let ext = std::path::Path::new(&path_in_tar)
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("");

            match ext {
                "hdb" => {
                    let mut buf = Vec::new();
                    entry.read_to_end(&mut buf).map_err(ScanError::Io)?;
                    let reader = BufReader::new(buf.as_slice());
                    self.parse_hash_lines(reader, HashType::Md5, &path_in_tar)?;
                }
                "msb" => {
                    let mut buf = Vec::new();
                    entry.read_to_end(&mut buf).map_err(ScanError::Io)?;
                    let reader = BufReader::new(buf.as_slice());
                    self.parse_hash_lines(reader, HashType::Sha256, &path_in_tar)?;
                }
                _ => {}
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum HashType {
    Md5,
    Sha256,
}

fn metadata_date(dir: &Path) -> Option<String> {
    std::fs::metadata(dir)
        .ok()
        .and_then(|m| m.modified().ok())
        .map(|t| {
            let dt: chrono::DateTime<chrono::Utc> = t.into();
            dt.format("%Y-%m-%d %H:%M UTC").to_string()
        })
}
