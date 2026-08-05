//! Workspace-level error taxonomy.

use thiserror::Error;

/// Top-level error type for the Aloo platform.
#[derive(Debug, Error)]
pub enum AlooError {
    /// Scan failed.
    #[error("Scan error: {0}")]
    Scan(String),
    /// Configuration invalid.
    #[error("Configuration error: {0}")]
    Config(String),
    /// Storage / persistence error.
    #[error("Storage error: {0}")]
    Storage(String),
    /// Plugin error.
    #[error("Plugin error: {0}")]
    Plugin(String),
    /// Reporting error.
    #[error("Report error: {0}")]
    Report(String),
    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// Internal / unexpected error.
    #[error("Internal error: {0}")]
    Internal(String),
}

/// Convenience `Result` alias.
pub type AlooResult<T> = Result<T, AlooError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_includes_message() {
        let e = AlooError::Config("missing field".to_string());
        assert!(e.to_string().contains("missing field"));
    }

    #[test]
    fn io_error_converts() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file gone");
        let aloo_err: AlooError = io_err.into();
        assert!(aloo_err.to_string().contains("file gone"));
    }
}
