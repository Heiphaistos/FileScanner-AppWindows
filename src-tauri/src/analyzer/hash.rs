use md5::Md5;
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::Path;

use crate::error::ScanError;
use crate::report::types::Hashes;

const CHUNK_SIZE: usize = 8 * 1024 * 1024; // 8 MB

/// Calcul SHA-256 + MD5 en streaming pour fichiers > 100 MB.
pub fn compute(path: &Path) -> Result<Hashes, ScanError> {
    let mut file = std::fs::File::open(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            ScanError::AccessDenied(path.display().to_string())
        } else {
            ScanError::Io(e)
        }
    })?;

    let mut sha256 = Sha256::new();
    let mut md5 = Md5::new();
    let mut buffer = vec![0u8; CHUNK_SIZE];

    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        sha256.update(&buffer[..n]);
        md5.update(&buffer[..n]);
    }

    Ok(Hashes {
        sha256: hex::encode(sha256.finalize()),
        md5: hex::encode(md5.finalize()),
    })
}
