use thiserror::Error;
use std::path::PathBuf;

/// Flawless error handling enum for the entire scanner domain.
#[derive(Error, Debug)]
pub enum ScannerError {
    #[error("Failed to parse or load language grammar for {0}")]
    GrammarError(String),
    
    #[error("Failed to read file from path: {0}")]
    FileReadError(PathBuf),

    #[error("Tree-sitter mathematical query execution failed: {0}")]
    QueryError(String),

    #[error("Invalid UTF-8 sequence encountered in file: {0}")]
    EncodingError(PathBuf),
}
