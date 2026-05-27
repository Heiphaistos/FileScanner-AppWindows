use std::path::Path;

/// Détecte le type MIME réel (magic bytes) indépendamment de l'extension.
pub fn detect(path: &Path) -> String {
    tree_magic_mini::from_filepath(path)
        .map(|s| s.to_string())
        .unwrap_or_else(|| "application/octet-stream".to_string())
}

/// Catégorie de fichier à partir du MIME.
pub enum FileCategory {
    Pe,      // EXE/DLL
    Script,  // BAT/PS1/VBS/JS
    Archive, // ZIP/RAR/7z
    Document,
    Other,
}

pub fn categorize(mime: &str, path: &Path) -> FileCategory {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    if mime == "application/x-dosexec"
        || mime == "application/x-executable"
        || ext == "exe"
        || ext == "dll"
        || ext == "sys"
        || ext == "ocx"
    {
        return FileCategory::Pe;
    }

    if matches!(ext.as_str(), "bat" | "cmd" | "ps1" | "vbs" | "js" | "wsf" | "hta") {
        return FileCategory::Script;
    }

    if mime.contains("zip")
        || mime.contains("rar")
        || mime.contains("7z")
        || mime.contains("tar")
        || mime.contains("gzip")
    {
        return FileCategory::Archive;
    }

    if mime.contains("pdf")
        || mime.contains("word")
        || mime.contains("excel")
        || mime.contains("office")
    {
        return FileCategory::Document;
    }

    FileCategory::Other
}
