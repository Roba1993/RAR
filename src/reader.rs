//! Reading single files of an archive without extracting it.
//!
//! [`ArchiveReader::open`] reads only the headers of an archive (and of all
//! its volumes) and remembers where the data of every file is stored. A file
//! can then be read with an [`EntryReader`], which implements [`Read`] and
//! [`Seek`]:
//!
//! - Stored files (`-m0`) support real random access, also when they're
//!   encrypted or split over several volumes. AES-CBC allows decrypting any
//!   16 byte block with the ciphertext block before it as IV.
//! - Compressed files are decompressed as a stream. Seeking forward decodes
//!   and drops the data in between, seeking backward starts over. In a solid
//!   archive the compressed files before the file are decoded first.

use crate::aes_reader::{FileKeys, RarAesReader};
use crate::archive_block::ArchiveBlock;
use crate::compression::CompressionReader;
use crate::end_block::EndBlock;
use crate::error::{RarError, Result};
use crate::extractor::next_volume_name;
use crate::file_block::{CompressionFlags, FileBlock};
use crate::head_block::{HeadBlock, Typ};
use crate::sig_block::SignatureBlock;
use aes::Aes256;
use cbc::cipher::{block_padding::NoPadding, BlockModeDecrypt, KeyIvInit};
use std::fs::File;
use std::io::{self, BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;

type Aes256CbcDec = cbc::Decryptor<Aes256>;

/// Largest header the RAR 5.0 format allows (2 MB).
const MAX_HEADER_SIZE: u64 = 2 * 1024 * 1024;

/// Size of the chunks read from the archive while decrypting or skipping.
const CHUNK_SIZE: usize = 0x1_0000;

/// An archive opened for reading single files.
///
/// ```no_run
/// use std::io::{Read, Seek, SeekFrom};
///
/// let archive = rar::ArchiveReader::open("archive.part1.rar", "password")?;
/// for entry in archive.entries() {
///     println!("{} ({} bytes)", entry.name(), entry.size());
/// }
///
/// let mut reader = archive.reader_by_name("video.mkv")?;
/// reader.seek(SeekFrom::Start(1_000_000))?;
/// let mut buf = vec![0; 4096];
/// reader.read_exact(&mut buf)?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone)]
pub struct ArchiveReader {
    shared: Arc<Shared>,
}

#[derive(Debug)]
struct Shared {
    volumes: Vec<PathBuf>,
    entries: Vec<Entry>,
    password: String,
}

/// A file or directory of an archive.
#[derive(Debug, Clone)]
pub struct Entry {
    block: FileBlock,
    segments: Vec<Segment>,
}

/// Part of the data area of an entry, stored in one volume.
#[derive(Debug, Clone, Copy, PartialEq)]
struct Segment {
    volume: usize,
    offset: u64,
    len: u64,
}

impl Entry {
    /// Path of the entry inside the archive.
    pub fn name(&self) -> &str {
        &self.block.name
    }

    /// Size of the file content (0 for directories).
    pub fn size(&self) -> u64 {
        if self.is_dir() {
            0
        } else {
            self.block.unpacked_size
        }
    }

    pub fn is_dir(&self) -> bool {
        self.block.flags.directory
    }

    pub fn is_encrypted(&self) -> bool {
        self.block.extra.file_encryption.is_some()
    }

    /// True unless the file is stored without compression.
    pub fn is_compressed(&self) -> bool {
        self.block.compression.flag != CompressionFlags::Save
    }

    /// True if the file continues the compression stream of the files before it.
    pub fn is_solid(&self) -> bool {
        self.is_compressed() && self.block.compression.solid
    }

    /// True if any position can be read without decoding the data before it.
    pub fn supports_random_access(&self) -> bool {
        !self.is_compressed()
    }

    /// The parsed file header (of the last volume for split files).
    pub fn block(&self) -> &FileBlock {
        &self.block
    }

    fn data_len(&self) -> u64 {
        self.segments.iter().map(|s| s.len).sum()
    }
}

impl ArchiveReader {
    /// Read the headers of the archive at `path`.
    ///
    /// For a multi-volume archive pass the first volume (`name.part1.rar`);
    /// the other volumes are opened as well. Only the headers are read, the
    /// file data is skipped. `password` is used when reading encrypted files.
    pub fn open(path: impl AsRef<Path>, password: &str) -> Result<ArchiveReader> {
        let first = path.as_ref().to_path_buf();
        let mut volumes = vec![];
        let mut entries: Vec<Entry> = vec![];
        let mut current = first.clone();

        loop {
            let volume = volumes.len();
            let more = index_volume(&current, volume, &mut entries)?;
            volumes.push(current);
            if !more {
                break;
            }
            let name = first.to_str().ok_or_else(|| RarError::FileNotFound {
                filename: format!("next volume of {}", first.display()),
            })?;
            current = next_volume_name(name, volume + 1)
                .ok_or_else(|| RarError::FileNotFound {
                    filename: format!("next volume of {}", name),
                })?
                .into();
        }

        if let Some(entry) = entries.iter().find(|e| e.block.head.flags.data_next) {
            return Err(RarError::FileNotFound {
                filename: format!("next volume with the rest of {}", entry.name()),
            });
        }

        Ok(ArchiveReader {
            shared: Arc::new(Shared {
                volumes,
                entries,
                password: password.to_string(),
            }),
        })
    }

    /// All files and directories in archive order.
    pub fn entries(&self) -> &[Entry] {
        &self.shared.entries
    }

    /// The paths of all volumes of the archive.
    pub fn volumes(&self) -> &[PathBuf] {
        &self.shared.volumes
    }

    /// A reader for the entry at `index` of [`entries`](Self::entries).
    pub fn reader(&self, index: usize) -> Result<EntryReader> {
        let entry = self
            .shared
            .entries
            .get(index)
            .ok_or_else(|| RarError::FileNotFound {
                filename: format!("entry #{}", index),
            })?;
        EntryReader::new(&self.shared, index, entry)
    }

    /// A reader for the entry with the path `name`.
    pub fn reader_by_name(&self, name: &str) -> Result<EntryReader> {
        let index = self
            .shared
            .entries
            .iter()
            .position(|e| e.name() == name)
            .ok_or_else(|| RarError::FileNotFound {
                filename: name.to_string(),
            })?;
        self.reader(index)
    }
}

/// Add the entries of one volume to `entries`. Returns true if another
/// volume follows.
fn index_volume(path: &Path, volume: usize, entries: &mut Vec<Entry>) -> Result<bool> {
    let mut file = BufReader::new(File::open(path)?);

    let mut sig = [0u8; 8];
    file.read_exact(&mut sig)
        .map_err(|_| RarError::InvalidSignature)?;
    if !matches!(SignatureBlock::parse(&sig), Ok((_, SignatureBlock::RAR5))) {
        return Err(RarError::InvalidSignature);
    }

    let mut multivolume = false;
    let mut more = false;
    while let Some(header) = read_header(&mut file)? {
        let (_, head) = HeadBlock::parse(&header).map_err(|_| RarError::ParserError)?;
        match head.typ {
            Typ::MainArchive => {
                let (_, block) =
                    ArchiveBlock::parse(&header).map_err(|_| RarError::InvalidArchiveBlock)?;
                if block.volume_number != volume as u64 {
                    return Err(RarError::InvalidArchiveBlock);
                }
                multivolume = block.flags.multivolume;
            }
            Typ::File => {
                let (_, block) =
                    FileBlock::parse(&header).map_err(|_| RarError::InvalidFileBlock)?;
                let segment = Segment {
                    volume,
                    offset: file.stream_position()?,
                    len: head.data_area_size,
                };
                if block.head.flags.data_prev {
                    // continuation of the last file of the previous volume
                    let entry = entries
                        .last_mut()
                        .filter(|e| e.block.head.flags.data_next && e.block.name == block.name)
                        .ok_or(RarError::InvalidFileBlock)?;
                    entry.segments.push(segment);
                    // the header of the last part holds the checksum of the whole file
                    entry.block = block;
                } else {
                    entries.push(Entry {
                        block,
                        segments: vec![segment],
                    });
                }
            }
            Typ::Encryption => return Err(RarError::EncryptedHeaders),
            Typ::EndArchive => {
                let (_, end) = EndBlock::parse(&header).map_err(|_| RarError::InvalidEnd)?;
                more = !end.last_volume;
                break;
            }
            // service headers (comment, quick open, recovery record, ...)
            Typ::Service | Typ::Unknown => {}
        }
        let skip = i64::try_from(head.data_area_size).map_err(|_| RarError::ParserError)?;
        file.seek_relative(skip)?;
    }
    Ok(multivolume && more)
}

/// Read the next complete header block, `None` at the end of the file.
fn read_header<R: Read>(reader: &mut R) -> Result<Option<Vec<u8>>> {
    let mut header = vec![0u8; 4];
    match reader.read_exact(&mut header) {
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        other => other?,
    }

    // header size as vint, counting the bytes after it
    let mut size = 0u64;
    for shift in (0..).step_by(7) {
        if shift > 21 {
            return Err(RarError::CorruptHeader);
        }
        let mut byte = [0u8];
        reader.read_exact(&mut byte)?;
        header.push(byte[0]);
        size |= u64::from(byte[0] & 0x7f) << shift;
        if byte[0] & 0x80 == 0 {
            break;
        }
    }
    if size == 0 || size > MAX_HEADER_SIZE {
        return Err(RarError::CorruptHeader);
    }

    let start = header.len();
    header.resize(start + size as usize, 0);
    reader.read_exact(&mut header[start..])?;

    let crc = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
    if crc32fast::hash(&header[4..]) != crc {
        return Err(RarError::CorruptHeader);
    }
    Ok(Some(header))
}

/// Reader of the raw data area of an entry, spread over the volumes.
struct DataArea {
    shared: Arc<Shared>,
    segments: Vec<Segment>,
    len: u64,
    pos: u64,
    /// open volume, its index and the position of the file
    file: Option<(usize, BufReader<File>, u64)>,
}

impl DataArea {
    fn new(shared: &Arc<Shared>, entry: &Entry) -> DataArea {
        DataArea {
            shared: Arc::clone(shared),
            segments: entry.segments.clone(),
            len: entry.data_len(),
            pos: 0,
            file: None,
        }
    }
}

impl Read for DataArea {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut start = 0;
        let Some(segment) = self.segments.iter().copied().find(|s| {
            start += s.len;
            self.pos < start
        }) else {
            return Ok(0);
        };
        let within = self.pos - (start - segment.len);
        let target = segment.offset + within;

        if self.file.as_ref().is_none_or(|f| f.0 != segment.volume) {
            let file = File::open(&self.shared.volumes[segment.volume])?;
            self.file = Some((segment.volume, BufReader::new(file), 0));
        }
        let (_, file, pos) = self.file.as_mut().expect("volume is open");
        if *pos != target {
            file.seek(SeekFrom::Start(target))?;
            *pos = target;
        }

        let max = buf
            .len()
            .min(usize::try_from(segment.len - within).unwrap_or(usize::MAX));
        let n = file.read(&mut buf[..max])?;
        if n == 0 && max > 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        *pos += n as u64;
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for DataArea {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.pos = match pos {
            SeekFrom::Start(p) => Some(p),
            SeekFrom::End(d) => self.len.checked_add_signed(d),
            SeekFrom::Current(d) => self.pos.checked_add_signed(d),
        }
        .ok_or(io::ErrorKind::InvalidInput)?;
        Ok(self.pos)
    }
}

/// Random access decryption of an AES-256-CBC encrypted data area.
struct AesSeekReader {
    data: DataArea,
    key: [u8; 32],
    init: [u8; 16],
    /// decrypted data starting at `plain_start`
    plain: Vec<u8>,
    plain_start: u64,
    /// IV for the block at `next_block`, the last decrypted ciphertext block
    iv: [u8; 16],
    next_block: Option<u64>,
}

impl AesSeekReader {
    fn new(data: DataArea, key: [u8; 32], init: [u8; 16]) -> AesSeekReader {
        AesSeekReader {
            data,
            key,
            init,
            plain: vec![],
            plain_start: 0,
            iv: init,
            next_block: None,
        }
    }

    /// Decrypt the data at `pos`, which must be a multiple of 16.
    fn decrypt_at(&mut self, pos: u64) -> io::Result<()> {
        if self.next_block != Some(pos) {
            // CBC: the IV of a block is the ciphertext block before it
            if pos == 0 {
                self.iv = self.init;
            } else {
                self.data.seek(SeekFrom::Start(pos - 16))?;
                self.data.read_exact(&mut self.iv)?;
            }
            self.data.seek(SeekFrom::Start(pos))?;
        }

        let available = self.data.len.saturating_sub(pos) & !15;
        let len = usize::try_from(available)
            .unwrap_or(usize::MAX)
            .min(CHUNK_SIZE);
        let mut data = vec![0u8; len];
        self.data.read_exact(&mut data)?;

        if len > 0 {
            let mut next_iv = [0u8; 16];
            next_iv.copy_from_slice(&data[len - 16..]);
            Aes256CbcDec::new(&self.key.into(), &self.iv.into())
                .decrypt_padded::<NoPadding>(&mut data)
                .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
            self.iv = next_iv;
        }
        self.plain = data;
        self.plain_start = pos;
        self.next_block = Some(pos + len as u64);
        Ok(())
    }

    fn read_at(&mut self, pos: u64, buf: &mut [u8]) -> io::Result<usize> {
        let end = self.plain_start + self.plain.len() as u64;
        if pos < self.plain_start || pos >= end {
            self.decrypt_at(pos & !15)?;
        }
        let offset = (pos - self.plain_start) as usize;
        let n = buf.len().min(self.plain.len().saturating_sub(offset));
        buf[..n].copy_from_slice(&self.plain[offset..offset + n]);
        Ok(n)
    }
}

/// Decompressing reader, which starts over to go back.
struct PackedReader {
    shared: Arc<Shared>,
    index: usize,
    stream: Option<CompressionReader<RarAesReader<DataArea>>>,
    stream_pos: u64,
}

impl PackedReader {
    /// Open the stream of the entry at `index`, after decoding the files of
    /// the solid stream before it.
    fn open_stream(&self) -> Result<CompressionReader<RarAesReader<DataArea>>> {
        let entries = &self.shared.entries;
        let mut chain = vec![];
        if entries[self.index].is_solid() {
            for (i, entry) in entries[..self.index].iter().enumerate().rev() {
                // stored files and directories aren't part of the solid stream
                if entry.is_dir() || !entry.is_compressed() {
                    continue;
                }
                chain.push(i);
                if !entry.is_solid() {
                    break;
                }
            }
        }

        let mut solid = None;
        for &i in chain.iter().rev() {
            let entry = &entries[i];
            let mut stream = open_compressed(&self.shared, entry, &mut solid)?;
            let size = entry.block.unpacked_size;
            let copied = io::copy(&mut (&mut stream).take(size), &mut io::sink())?;
            if copied != size {
                return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
            }
            solid = stream.into_solid_state();
        }
        open_compressed(&self.shared, &entries[self.index], &mut solid)
    }

    fn read_at(&mut self, pos: u64, buf: &mut [u8]) -> io::Result<usize> {
        if self.stream.is_none() || self.stream_pos > pos {
            self.stream = Some(self.open_stream().map_err(into_io)?);
            self.stream_pos = 0;
        }
        let stream = self.stream.as_mut().expect("stream is open");

        // decode and drop the data up to `pos`
        let mut scratch = vec![];
        while self.stream_pos < pos {
            let len = usize::try_from(pos - self.stream_pos)
                .unwrap_or(usize::MAX)
                .min(CHUNK_SIZE);
            scratch.resize(len, 0);
            let n = stream.read(&mut scratch)?;
            if n == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            self.stream_pos += n as u64;
        }

        let n = stream.read(buf)?;
        self.stream_pos += n as u64;
        Ok(n)
    }
}

/// Check the password and derive the keys of an encrypted entry.
fn entry_keys(shared: &Shared, entry: &Entry) -> Result<Option<FileKeys>> {
    let Some(feb) = &entry.block.extra.file_encryption else {
        return Ok(None);
    };
    let keys = FileKeys::derive(feb, &shared.password);
    if !keys.password_matches(feb) {
        return Err(RarError::WrongPassword {
            filename: entry.block.name.clone(),
        });
    }
    Ok(Some(keys))
}

fn open_compressed(
    shared: &Arc<Shared>,
    entry: &Entry,
    solid: &mut Option<crate::compression::SolidState>,
) -> Result<CompressionReader<RarAesReader<DataArea>>> {
    let keys = entry_keys(shared, entry)?;
    let aes_key = keys
        .zip(entry.block.extra.file_encryption.as_ref())
        .map(|(k, feb)| (k.key, feb.init));
    let data = RarAesReader::new(DataArea::new(shared, entry), aes_key);
    CompressionReader::new(data, &entry.block, solid)
}

fn into_io(e: RarError) -> io::Error {
    match e {
        RarError::Io(e) => e,
        e => io::Error::other(e),
    }
}

enum Source {
    Stored(DataArea),
    Encrypted(AesSeekReader),
    Packed(PackedReader),
}

impl Source {
    fn read_at(&mut self, pos: u64, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Source::Stored(data) => {
                data.seek(SeekFrom::Start(pos))?;
                data.read(buf)
            }
            Source::Encrypted(aes) => aes.read_at(pos, buf),
            Source::Packed(packed) => packed.read_at(pos, buf),
        }
    }
}

/// Reader of the content of one entry, see [`ArchiveReader`].
///
/// When the whole file is read from the start without seeking, its checksum
/// is verified at the end and a mismatch is returned as an
/// [`io::ErrorKind::InvalidData`] error.
pub struct EntryReader {
    source: Source,
    name: String,
    pos: u64,
    size: u64,
    random_access: bool,
    /// running checksum while the data has been read in order from the start
    crc: Option<(crc32fast::Hasher, u64)>,
    expected_crc: Option<u32>,
    keys: Option<FileKeys>,
    tweaked_crc: bool,
}

impl EntryReader {
    fn new(shared: &Arc<Shared>, index: usize, entry: &Entry) -> Result<EntryReader> {
        let keys = entry_keys(shared, entry)?;
        let source = if entry.is_dir() || entry.is_compressed() {
            Source::Packed(PackedReader {
                shared: Arc::clone(shared),
                index,
                stream: None,
                stream_pos: 0,
            })
        } else {
            let data = DataArea::new(shared, entry);
            match (&keys, &entry.block.extra.file_encryption) {
                (Some(keys), Some(feb)) => {
                    Source::Encrypted(AesSeekReader::new(data, keys.key, feb.init))
                }
                _ => Source::Stored(data),
            }
        };

        let block = &entry.block;
        Ok(EntryReader {
            source,
            name: block.name.clone(),
            pos: 0,
            size: entry.size(),
            random_access: entry.supports_random_access(),
            crc: Some((crc32fast::Hasher::new(), 0)),
            expected_crc: block.flags.crc.then_some(block.data_crc),
            tweaked_crc: block
                .extra
                .file_encryption
                .as_ref()
                .is_some_and(|feb| feb.flags.tweaked_crc),
            keys,
        })
    }

    /// Size of the content.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// True if seeking is cheap. Otherwise seeking forward decodes the data in
    /// between and seeking backward decodes the file again from the start.
    pub fn supports_random_access(&self) -> bool {
        self.random_access
    }

    fn verify_crc(&mut self) -> io::Result<()> {
        let (Some((hasher, _)), Some(expected)) = (self.crc.take(), self.expected_crc) else {
            return Ok(());
        };
        let crc = hasher.finalize();
        let actual = match &self.keys {
            Some(keys) if self.tweaked_crc => keys.tweak_crc(crc),
            _ => crc,
        };
        if actual != expected {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                RarError::ChecksumMismatch {
                    filename: self.name.clone(),
                    expected,
                    actual,
                },
            ));
        }
        Ok(())
    }
}

impl Read for EntryReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.size || buf.is_empty() {
            return Ok(0);
        }
        let max = buf
            .len()
            .min(usize::try_from(self.size - self.pos).unwrap_or(usize::MAX));
        let n = self.source.read_at(self.pos, &mut buf[..max])?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!(
                    "{}: data ends at {} of {} bytes",
                    self.name, self.pos, self.size
                ),
            ));
        }

        match &mut self.crc {
            Some((hasher, at)) if *at == self.pos => {
                hasher.update(&buf[..n]);
                *at += n as u64;
            }
            _ => self.crc = None,
        }
        self.pos += n as u64;
        if self.pos == self.size {
            self.verify_crc()?;
        }
        Ok(n)
    }
}

impl Seek for EntryReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.pos = match pos {
            SeekFrom::Start(p) => Some(p),
            SeekFrom::End(d) => self.size.checked_add_signed(d),
            SeekFrom::Current(d) => self.pos.checked_add_signed(d),
        }
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "seek before the start"))?;
        Ok(self.pos)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_file(path: &str) -> Vec<u8> {
        std::fs::read(path).unwrap()
    }

    fn read_all(reader: &mut EntryReader) -> Vec<u8> {
        let mut data = vec![];
        reader.read_to_end(&mut data).unwrap();
        data
    }

    /// Read `len` bytes at `pos` and compare them with `expected`.
    fn check_range(reader: &mut EntryReader, expected: &[u8], pos: usize, len: usize) {
        let len = len.min(expected.len() - pos);
        reader.seek(SeekFrom::Start(pos as u64)).unwrap();
        let mut buf = vec![0u8; len];
        reader.read_exact(&mut buf).unwrap();
        assert_eq!(buf, &expected[pos..pos + len], "range {}+{}", pos, len);
    }

    /// Positions spread over the file, in an unordered sequence.
    fn positions(len: usize) -> Vec<usize> {
        let mut positions: Vec<usize> = (0..40).map(|i| (i * 7919 * 104729) % len).collect();
        positions.extend([0, 1, 15, 16, 17, len - 1, len / 2, 4095, 65535, 65536]);
        positions.retain(|&p| p < len);
        positions
    }

    fn check_random_access(rar: &str, password: &str, name: &str, original: &str) {
        let archive = ArchiveReader::open(rar, password).unwrap();
        let expected = read_file(original);
        let mut reader = archive.reader_by_name(name).unwrap();
        assert_eq!(reader.size(), expected.len() as u64);
        assert!(reader.supports_random_access());
        for pos in positions(expected.len()) {
            check_range(&mut reader, &expected, pos, 1000);
        }
        // reading to the end after seeking works and skips the checksum
        reader.seek(SeekFrom::End(-10)).unwrap();
        assert_eq!(read_all(&mut reader), &expected[expected.len() - 10..]);
        // and so does a complete read, which verifies the checksum
        reader.seek(SeekFrom::Start(0)).unwrap();
        assert_eq!(
            read_all(&mut archive.reader_by_name(name).unwrap()),
            expected
        );
    }

    #[test]
    fn test_list_entries() {
        let archive = ArchiveReader::open("assets/rar5-normal-32mb-txt-png.rar", "").unwrap();
        let names: Vec<_> = archive.entries().iter().map(Entry::name).collect();
        assert_eq!(names, ["photo.jpg", "text.txt"]);
        assert_eq!(archive.entries()[0].size(), 2149083);
        assert_eq!(archive.volumes().len(), 1);
    }

    #[test]
    fn test_list_multi_volume() {
        let archive =
            ArchiveReader::open("assets/rar5-save-32mb-txt-png-512kb.part1.rar", "").unwrap();
        assert_eq!(archive.volumes().len(), 5);
        let photo = archive
            .entries()
            .iter()
            .find(|e| e.name() == "photo.jpg")
            .unwrap();
        assert!(photo.segments.len() > 1);
        assert_eq!(photo.data_len(), 2149083);
    }

    #[test]
    fn test_random_access_stored() {
        check_random_access(
            "assets/rar5-save-32mb-txt-png.rar",
            "",
            "photo.jpg",
            "assets/photo.jpg",
        );
    }

    #[test]
    fn test_random_access_stored_multi_volume() {
        check_random_access(
            "assets/rar5-save-32mb-txt-png-512kb.part1.rar",
            "",
            "photo.jpg",
            "assets/photo.jpg",
        );
    }

    #[test]
    fn test_random_access_stored_small_volumes() {
        // 13 volumes of 919 bytes with five copies of the text
        let archive = ArchiveReader::open("assets/rar5-save-txt-volumes.part01.rar", "").unwrap();
        assert_eq!(archive.volumes().len(), 13);
        for i in 1..=5 {
            check_random_access(
                "assets/rar5-save-txt-volumes.part01.rar",
                "",
                &format!("text{}.txt", i),
                "assets/text.txt",
            );
        }
    }

    #[test]
    fn test_random_access_encrypted() {
        check_random_access(
            "assets/rar5-save-32mb-txt-png-pw-test.rar",
            "test",
            "photo.jpg",
            "assets/photo.jpg",
        );
        check_random_access(
            "assets/rar5-save-32mb-txt-png-pw-test.rar",
            "test",
            "text.txt",
            "assets/text.txt",
        );
    }

    #[test]
    fn test_wrong_password() {
        let archive =
            ArchiveReader::open("assets/rar5-save-32mb-txt-png-pw-test.rar", "nope").unwrap();
        assert!(matches!(
            archive.reader_by_name("photo.jpg"),
            Err(RarError::WrongPassword { .. })
        ));
    }

    #[test]
    fn test_unknown_name() {
        let archive = ArchiveReader::open("assets/rar5-save-32mb-txt.rar", "").unwrap();
        assert!(matches!(
            archive.reader_by_name("missing.txt"),
            Err(RarError::FileNotFound { .. })
        ));
    }

    #[test]
    fn test_stream_compressed() {
        let text = read_file("assets/text.txt");
        for level in ["fastest", "fast", "normal", "good", "best"] {
            let rar = format!("assets/rar5-{}-32mb-txt.rar", level);
            let archive = ArchiveReader::open(&rar, "").unwrap();
            let mut reader = archive.reader_by_name("text.txt").unwrap();
            assert!(!reader.supports_random_access());
            assert_eq!(read_all(&mut reader), text, "{}", rar);
        }
    }

    #[test]
    fn test_seek_compressed() {
        let photo = read_file("assets/photo.jpg");
        let archive =
            ArchiveReader::open("assets/rar5-normal-32mb-txt-png-pw-test.rar", "test").unwrap();
        let mut reader = archive.reader_by_name("photo.jpg").unwrap();
        // forward and backward
        for pos in [100, 500_000, 2_000_000, 10, 1_000_000] {
            check_range(&mut reader, &photo, pos, 5000);
        }
    }

    #[test]
    fn test_compressed_multi_volume() {
        let archive = ArchiveReader::open(
            "assets/rar5-normal-32mb-txt-png-1mb-pw-test.part1.rar",
            "test",
        )
        .unwrap();
        assert_eq!(
            read_all(&mut archive.reader_by_name("photo.jpg").unwrap()),
            read_file("assets/photo.jpg")
        );
        assert_eq!(
            read_all(&mut archive.reader_by_name("text.txt").unwrap()),
            read_file("assets/text.txt")
        );
    }

    #[test]
    fn test_solid_archive() {
        let archive = ArchiveReader::open("assets/rar5-normal-32mb-txt-png-solid.rar", "").unwrap();
        // read the later files first, which decodes the ones before them
        for entry in archive.entries().iter().rev() {
            let expected = read_file(&format!("assets/{}", entry.name()));
            let mut reader = archive.reader_by_name(entry.name()).unwrap();
            assert_eq!(read_all(&mut reader), expected, "{}", entry.name());
            check_range(&mut reader, &expected, expected.len() / 3, 100);
        }
        assert!(archive.entries().iter().skip(1).any(Entry::is_solid));
    }

    #[test]
    fn test_directories() {
        let archive = ArchiveReader::open("assets/rar5-normal-dirs.rar", "").unwrap();
        assert!(archive.entries().iter().any(Entry::is_dir));
        for (i, entry) in archive.entries().iter().enumerate() {
            let data = read_all(&mut archive.reader(i).unwrap());
            assert_eq!(data.len() as u64, entry.size(), "{}", entry.name());
        }
    }

    #[test]
    fn test_checksum_mismatch() {
        // flip one byte of the stored text and read the whole file
        let mut data = read_file("assets/rar5-save-32mb-txt.rar");
        let text = read_file("assets/text.txt");
        let at = data.windows(16).position(|w| w == &text[..16]).unwrap();
        data[at + 100] ^= 0xff;
        let dir = std::env::temp_dir().join(format!("rar-crc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("corrupt.rar");
        std::fs::write(&path, &data).unwrap();

        let archive = ArchiveReader::open(&path, "").unwrap();
        let mut reader = archive.reader_by_name("text.txt").unwrap();
        let err = reader.read_to_end(&mut vec![]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_read_header_rejects_bad_crc() {
        let mut data = read_file("assets/rar5-save-32mb-txt.rar");
        data[8] ^= 0xff; // CRC of the main archive header
        let mut reader = &data[8..];
        assert!(matches!(
            read_header(&mut reader),
            Err(RarError::CorruptHeader)
        ));
    }

    #[test]
    fn test_skips_service_headers() {
        // the recovery record is stored in a service header
        let archive =
            ArchiveReader::open("assets/rar5-normal-32mb-txt-png-recovery.rar", "").unwrap();
        let names: Vec<_> = archive.entries().iter().map(Entry::name).collect();
        assert_eq!(names, ["photo.jpg", "text.txt"]);
    }

    #[test]
    fn test_unsupported_archives() {
        assert!(matches!(
            ArchiveReader::open("assets/rar5-normal-32mb-txt-png-pwf-test.rar", "test"),
            Err(RarError::EncryptedHeaders)
        ));
        assert!(matches!(
            ArchiveReader::open("assets/rar4-save-4096kb-txt.rar", ""),
            Err(RarError::InvalidSignature)
        ));
    }
}
