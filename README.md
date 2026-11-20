# RAR Rust
This crate provides a Rust native functionality to list and extract RAR files with RAR5 support.

Please have a look in the test section of the file `src/lib.rs` to see in detail which features are supported right now and how to use this crate.

A basic example to extract the complete archive:
```rust
extern crate rar;

// Get the archive information and extract everything
let archive = rar::Archive::extract_all(
    "assets/rar5-save-32mb-txt.rar",
    "target/rar-test/rar5-save-32mb-txt/",
    "").unwrap();

// Print out the archive structure information
println!("Result: {:?}", archive);
```

To read single files without extracting the archive, open it with
`ArchiveReader`. Only the headers are read; every file can then be read with
a reader that implements `Read` and `Seek`:
```rust
use std::io::{Read, Seek, SeekFrom};

let archive = rar::ArchiveReader::open("assets/rar5-save-32mb-txt-png-pw-test.rar", "test")?;
for entry in archive.entries() {
    println!("{} ({} bytes)", entry.name(), entry.size());
}

// read 1 KB at offset 1 MB
let mut reader = archive.reader_by_name("photo.jpg")?;
reader.seek(SeekFrom::Start(1024 * 1024))?;
let mut buf = vec![0; 1024];
reader.read_exact(&mut buf)?;
```

- Stored files (`-m0`) support random access, also when they're encrypted
  or split over several volumes.
- Compressed files are decompressed as a stream. Seeking forward decodes the
  data in between, seeking backward starts the file over. In a solid archive
  the compressed files before the file are decoded first.
- A file read completely from the start has its checksum verified.

## Unreleased
New:
- `ArchiveReader` lists an archive from its headers and reads single files
  with `Read + Seek`, with random access for stored files (also encrypted and
  multi-volume) and streaming for compressed files
- New `RarError` variants `EncryptedHeaders` and `CorruptHeader`

## Version 0.6.0
New:
- RAR5 decompression (algorithm version 5.0) for all methods, FASTEST through BEST
- Solid archives
- Compressed files combined with encryption and multi-volume archives
- Delta, x86 (E8/E8E9) and ARM filters
- CRC32 verification of every extracted file, including the HMAC based
  checksums of encrypted files
- Wrong passwords are reported as `RarError::WrongPassword`
- Directories and files in subdirectories are extracted

Changed (breaking):
- `Compression` fields are parsed with the RAR5 bit layout. `version`,
  `solid` and `dictonary` had wrong values before.
- `FileBlock::data_crc` and `mtime` are read little endian as specified;
  `data_crc` was byte swapped before.
- `RarError` is `#[non_exhaustive]` and has new variants:
  `UnsupportedCompressionVersion`, `MissingSolidState`, `WrongPassword`,
  `ChecksumMismatch` and `UnsafeFileName`.
- Entries with absolute paths or `..` are rejected instead of being written
  outside the target directory.
- A file which can't be extracted completely is removed.
- Minimum supported Rust version is 1.89.

# Features
**RAR 5**
- [x] Extract archive with single File
- [x] Extract archive with multiple Files
- [x] Extract split archive with multiple files
- [x] Extract encrypted archive
- [x] Extract compression SAVE
- [x] Extract compression FASTEST
- [x] Extract compression FAST
- [x] Extract compression NORMAL
- [x] Extract compression GOOD
- [x] Extract compression BEST
- [x] Extract solid archive
- [x] Extract directories
- [x] Read single files with random access (stored) or as a stream (compressed)
- [ ] Extract symbolic and hard links
- [ ] Extract archive with encrypted headers (`-hp`)
- [ ] Extract archive with recovery record
- [ ] RAR 7.0 compression format (dictionaries larger than 4 GB)

**RAR 4**
- [ ] Extract archive with single File
- [ ] Extract archive with multiple Files
- [ ] Extract split archive with multiple files
- [ ] Extract encrypted archive
- [ ] Extract compression SAVE
- [ ] Extract compression FASTEST
- [ ] Extract compression FAST
- [ ] Extract compression NORMAL
- [ ] Extract compression GOOD
- [ ] Extract compression BEST

# Contributing
Please contribute! 

The goal is to make this crate feature complete :)

If you need any kind of help, open an issue or write me an mail.
Pull requests are welcome!

## Implementation Status
Decompression lives in `src/compression/`. It follows the RAR 5.0 format
description and the unrar reference source (`unpack50.cpp`): block headers,
Huffman tables stored in the stream, LZ matches with repeated distances and
the post-processing filters. Output streams through a sliding window, so the
compressed data is never loaded completely into memory.

# License
Copyright © 2018 Robert Schütte

Distributed under the [MIT License](LICENSE).
