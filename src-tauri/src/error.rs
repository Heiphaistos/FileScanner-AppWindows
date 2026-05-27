use thiserror::Error;

#[derive(Debug, Error)]
pub enum ScanError {
    #[error("Erreur I/O : {0}")]
    Io(#[from] std::io::Error),

    #[error("Fichier verrouillé ou accès refusé : {0}")]
    AccessDenied(String),

    #[error("Analyse PE échouée : {0}")]
    PeParseError(String),

    #[error("Erreur HTTP VirusTotal : {0}")]
    HttpError(#[from] reqwest::Error),

    #[error("Clé API VirusTotal manquante ou invalide")]
    MissingApiKey,

    #[error("Erreur stockage sécurisé : {0}")]
    KeyringError(String),

    #[error("Erreur d'export : {0}")]
    ExportError(String),

    #[error("Erreur PDF : {0}")]
    PdfError(String),

    #[error("Erreur interne : {0}")]
    Internal(String),
}

impl From<ScanError> for String {
    fn from(e: ScanError) -> Self {
        e.to_string()
    }
}

impl From<keyring::Error> for ScanError {
    fn from(e: keyring::Error) -> Self {
        ScanError::KeyringError(e.to_string())
    }
}
