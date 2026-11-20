//! RAR5 decompression (compression algorithm version 5.0, used since RAR 5.0).
//!
//! The implementation follows the RAR 5.0 archive format description and the
//! unrar reference source (`unpack50.cpp`).

mod bit_reader;
mod filter;
mod huffman;
mod unpack5;

use crate::error::{RarError, Result};
use crate::file_block::{CompressionFlags, FileBlock};
use bit_reader::BitReader;
use std::io::{self, Read};
use unpack5::Unpack5;

/// Largest dictionary of the RAR 5.0 algorithm (4 GB, `128 KB << 15`).
const MAX_DICTIONARY_BITS: u8 = 15;

/// Decoder state passed from one file of a solid archive to the next.
pub(crate) struct SolidState(Box<Unpack5>);

/// Reader which turns the (decrypted) data area of a file into the file content.
pub(crate) struct CompressionReader<R: Read> {
    inner: Inner<R>,
}

enum Inner<R: Read> {
    Store(R),
    Unpack {
        bits: BitReader<R>,
        state: Box<Unpack5>,
    },
}

impl<R: Read> CompressionReader<R> {
    /// Create a reader for the data of `file`.
    ///
    /// `solid` holds the state of the previous compressed file. It's taken
    /// when `file` continues a solid stream; get it back with
    /// [`into_solid_state`](Self::into_solid_state) once the file is read.
    pub(crate) fn new(reader: R, file: &FileBlock, solid: &mut Option<SolidState>) -> Result<Self> {
        let compression = &file.compression;
        let inner = match compression.flag {
            CompressionFlags::Save => Inner::Store(reader),
            CompressionFlags::Unknown => return Err(RarError::UnsupportedCompression),
            _ => {
                // Only the RAR 5.0 algorithm is supported, not the RAR 7.0
                // variant for dictionaries above 4 GB.
                if compression.version != 0 || compression.dictonary > MAX_DICTIONARY_BITS {
                    return Err(RarError::UnsupportedCompressionVersion {
                        version: compression.version,
                        dictionary_kb: compression.dictionary_size() / 1024,
                    });
                }
                let dict_size = compression.dictionary_size();
                let state = if compression.solid {
                    // A solid file can't be decoded without its predecessors.
                    let SolidState(mut state) =
                        solid.take().ok_or_else(|| RarError::MissingSolidState {
                            filename: file.name.clone(),
                        })?;
                    state.start_file(file.unpacked_size, dict_size)?;
                    state
                } else {
                    Box::new(Unpack5::new(dict_size, file.unpacked_size)?)
                };
                Inner::Unpack {
                    bits: BitReader::new(reader),
                    state,
                }
            }
        };
        Ok(Self { inner })
    }

    /// The decoder state for a following solid file, `None` for stored files.
    pub(crate) fn into_solid_state(self) -> Option<SolidState> {
        match self.inner {
            Inner::Store(_) => None,
            Inner::Unpack { state, .. } => Some(SolidState(state)),
        }
    }
}

impl<R: Read> Read for CompressionReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match &mut self.inner {
            Inner::Store(reader) => reader.read(buf),
            Inner::Unpack { bits, state } => state.read(bits, buf),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file_block::Compression;

    fn compressed_file(unpacked_size: u64, solid: bool, dictonary: u8) -> FileBlock {
        FileBlock {
            unpacked_size,
            compression: Compression {
                version: 0,
                solid,
                flag: CompressionFlags::Normal,
                dictonary,
            },
            ..Default::default()
        }
    }

    #[test]
    fn test_solid_file_without_predecessor() {
        let file = compressed_file(10, true, 0);
        let result = CompressionReader::new(&[][..], &file, &mut None);
        assert!(matches!(result, Err(RarError::MissingSolidState { .. })));
    }

    #[test]
    fn test_rar7_dictionary_unsupported() {
        let file = compressed_file(10, false, 16);
        let result = CompressionReader::new(&[][..], &file, &mut None);
        assert!(matches!(
            result,
            Err(RarError::UnsupportedCompressionVersion {
                version: 0,
                dictionary_kb: 8_388_608
            })
        ));
    }

    #[test]
    fn test_huge_unpacked_size_does_not_panic() {
        // the window is limited by the dictionary, not by the claimed size
        let file = compressed_file(u64::MAX, false, 0);
        let mut reader = CompressionReader::new(&[0u8; 16][..], &file, &mut None).unwrap();
        assert!(reader.read(&mut [0u8; 16]).is_err());
    }

    #[test]
    fn test_garbage_input_fails() {
        let file = compressed_file(1000, false, 0);
        let data: Vec<u8> = (0..1000u32).map(|i| (i * 7919 % 251) as u8).collect();
        let mut reader = CompressionReader::new(&data[..], &file, &mut None).unwrap();
        assert!(io::copy(&mut reader, &mut io::sink()).is_err());
    }
}
