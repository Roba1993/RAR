use std::io;
use thiserror::Error;

#[derive(Error, Debug)]
#[non_exhaustive]
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

    /// The file uses a compression algorithm other than RAR 5.0, for example
    /// the RAR 7.0 format for dictionaries larger than 4 GB.
    #[error("Unsupported compression algorithm version {version} (dictionary {dictionary_kb} KB)")]
    UnsupportedCompressionVersion { version: u8, dictionary_kb: u64 },

    /// A file of a solid archive can only be extracted after the files before it.
    #[error("{filename} continues a solid stream, but the previous files weren't extracted")]
    MissingSolidState { filename: String },

    #[error("Wrong password for {filename}")]
    WrongPassword { filename: String },

    #[error("Checksum mismatch for {filename}: expected {expected:08x}, got {actual:08x}")]
    ChecksumMismatch {
        filename: String,
        expected: u32,
        actual: u32,
    },

    /// The archive encrypts its headers (`rar -hp`), which isn't supported.
    #[error("Archives with encrypted headers aren't supported")]
    EncryptedHeaders,

    /// A header is damaged or its checksum doesn't match.
    #[error("Corrupt archive header")]
    CorruptHeader,

    /// The file name is absolute or leaves the target directory.
    #[error("Unsafe file name in archive: {filename}")]
    UnsafeFileName { filename: String },
}

pub type Result<T> = std::result::Result<T, RarError>;
