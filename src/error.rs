use std::io;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum RarError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    #[error("Can't read RAR signature")]
    InvalidSignature,

    #[error("Can't read RAR archive block")]
    InvalidArchiveBlock,

    #[error("Can't read RAR file block")]
    InvalidFileBlock,

    #[error("Can't read RAR end")]
    InvalidEnd,

    #[error("Can't execute nom parser")]
    ParserError,

    #[error("File {filename} not found in archive")]
    FileNotFound { filename: String },

    #[error("Unsupported compression method")]
    UnsupportedCompression,
}

pub type Result<T> = std::result::Result<T, RarError>;
