extern crate aes;
extern crate cbc;
extern crate chrono;
extern crate hmac;
extern crate nom;
extern crate sha2;
extern crate thiserror;

#[cfg(test)]
#[macro_use]
extern crate lazy_static;

mod aes_reader;
mod archive_block;
mod compression;
mod end_block;
pub mod error;
mod extra_block;
mod extractor;
mod file_block;
mod file_writer;
mod head_block;
mod rar_reader;
mod reader;
mod sig_block;
mod util;
mod vint;

use crate::error::{RarError, Result};
use rar_reader::RarReader;
pub use reader::{ArchiveReader, Entry, EntryReader};
use std::fs::File;
use std::io::Read;

/// The rar archive representation
#[derive(PartialEq, Debug)]
pub struct Archive {
    pub version: sig_block::SignatureBlock,
    pub details: archive_block::ArchiveBlock,
    pub files: Vec<file_block::FileBlock>,
    pub quick_open: Option<file_block::FileBlock>,
    pub end: end_block::EndBlock,
}

impl Archive {
    /// This function extracts the .rar archive and returns the parsed
    /// structure as additional information
    pub fn extract_all(file_name: &str, path: &str, password: &str) -> Result<Archive> {
        // Open a file reader
        let reader = File::open(file_name)?;
        // initilize the buffer
        let mut reader = RarReader::new_from_file(reader);

        // try to parse the signature
        let version = reader
            .exec_nom_parser(sig_block::SignatureBlock::parse)
            .map_err(|_| RarError::InvalidSignature)?;
        // try to parse the archive information
        let details = reader
            .exec_nom_parser(archive_block::ArchiveBlock::parse)
            .map_err(|_| RarError::InvalidArchiveBlock)?;

        let mut files = vec![];
        let mut quick_open = None;
        let mut file_number = 1;
        let mut solid_state = None;
        // loop over the packages and define how to handle them
        while let Ok(mut f) = reader.exec_nom_parser(file_block::FileBlock::parse) {
            // quick open file?
            if f.name == "QO" {
                reader.r_seek(f.head.data_area_size)?;
                quick_open = Some(f);
                break;
            }

            // limit the reader, because the rest of the file is not important,
            // when we have multiple files
            if f.head.flags.data_next {
                reader = RarReader::new(reader.take(f.head.data_area_size));
            }

            // create a new reader which chains the different data areas
            // between the different .rar files to extract the right one
            let mut data_area_size = f.head.data_area_size;
            while f.head.flags.data_next {
                reader = extractor::continue_data_next_file(
                    reader,
                    &mut f,
                    file_name,
                    &mut file_number,
                    &mut data_area_size,
                )?;
            }

            // extract all the data
            extractor::extract(
                &f,
                path,
                &mut reader,
                data_area_size,
                password,
                &mut solid_state,
            )?;

            // add the file to the array
            files.push(f);
        }

        // Get the end block
        let end = reader
            .exec_nom_parser(end_block::EndBlock::parse)
            .map_err(|_| RarError::InvalidEnd)?;

        // return the archive information
        Ok(Archive {
            version,
            details,
            files,
            quick_open,
            end,
        })
    }

    /// Parse RAR archive from memory buffer (similar to zip::ZipArchive::new)
    /// This enables in-memory parsing without requiring temporary files
    pub fn from_bytes(data: &[u8], _password: &str) -> Result<Archive> {
        use std::io::Cursor;

        let cursor = Cursor::new(data);
        let mut reader = RarReader::new(cursor);

        // Parse the signature
        let version = reader
            .exec_nom_parser(sig_block::SignatureBlock::parse)
            .map_err(|_| RarError::InvalidSignature)?;

        // Parse the archive information
        let details = reader
            .exec_nom_parser(archive_block::ArchiveBlock::parse)
            .map_err(|_| RarError::InvalidArchiveBlock)?;

        let mut files = vec![];
        let mut quick_open = None;

        // Parse file blocks (metadata only, no extraction)
        while let Ok(f) = reader.exec_nom_parser(file_block::FileBlock::parse) {
            // Handle quick open file
            if f.name == "QO" {
                reader.r_seek(f.head.data_area_size)?;
                quick_open = Some(f);
                break;
            }

            // Skip data area for metadata-only parsing
            reader.r_seek(f.head.data_area_size)?;

            // Add file metadata to list
            files.push(f);
        }

        // Parse the end block
        let end = reader
            .exec_nom_parser(end_block::EndBlock::parse)
            .map_err(|_| RarError::InvalidEnd)?;

        // Return archive structure with file metadata
        Ok(Archive {
            version,
            details,
            files,
            quick_open,
            end,
        })
    }
}

/********************** All .rar file test **********************/
#[cfg(test)]
mod tests {
    use crate::error::RarError;
    use crate::file_block::CompressionFlags;
    use crate::sig_block::SignatureBlock;
    use crate::Archive;
    use std::fs::{remove_dir_all, File};
    use std::io::Read;

    // Small helper function to read a file
    fn read_file(path: &str) -> Vec<u8> {
        let mut data = vec![];
        let mut file = File::open(path).unwrap();
        file.read_to_end(&mut data).unwrap();
        data
    }

    // Load the original files once so that every test can compare them
    lazy_static! {
        static ref PHOTO: Vec<u8> = read_file("assets/photo.jpg");
        static ref TEXT: Vec<u8> = read_file("assets/text.txt");
    }

    /// Extract `rar` and compare every expected file byte by byte.
    fn check_extract(rar: &str, password: &str, expected: &[(&str, &[u8])]) -> Archive {
        let out = format!("target/rar-test/{}/", rar);
        let _ = remove_dir_all(&out);

        let archive = Archive::extract_all(&format!("assets/{}.rar", rar), &out, password)
            .unwrap_or_else(|e| panic!("{}: extraction failed: {:?}", rar, e));

        assert_eq!(archive.version, SignatureBlock::RAR5);
        assert_eq!(archive.files.len(), expected.len(), "{}: file count", rar);
        for (name, data) in expected {
            let extracted = read_file(&format!("{}{}", out, name));
            assert!(
                extracted == *data,
                "{}: {} differs from the original ({} vs {} bytes)",
                rar,
                name,
                extracted.len(),
                data.len()
            );
        }

        remove_dir_all(&out).unwrap();
        archive
    }

    fn assert_method(archive: &Archive, name: &str, flag: CompressionFlags) {
        let file = archive.files.iter().find(|f| f.name == name).unwrap();
        assert_eq!(file.compression.flag, flag, "{}", name);
    }

    #[test]
    fn test_rar5_save_32mb_txt() {
        let archive = check_extract("rar5-save-32mb-txt", "test", &[("text.txt", &TEXT)]);

        assert_eq!(archive.files[0].name, "text.txt");
        assert_eq!(archive.files[0].unpacked_size, 2118);
        assert_method(&archive, "text.txt", CompressionFlags::Save);
    }

    /// The photo and text archives all list photo.jpg first and end with a QO block.
    fn assert_txt_png_layout(archive: &Archive) {
        assert_eq!(archive.files[0].name, "photo.jpg");
        assert_eq!(archive.files[0].unpacked_size, 2149083);
        assert_eq!(archive.files[1].name, "text.txt");
        assert_eq!(archive.files[1].unpacked_size, 2118);
        assert_eq!(archive.quick_open.as_ref().unwrap().name, "QO");
    }

    #[test]
    fn test_rar5_save_32mb_txt_png() {
        let archive = check_extract(
            "rar5-save-32mb-txt-png",
            "test",
            &[("photo.jpg", &PHOTO), ("text.txt", &TEXT)],
        );
        assert_txt_png_layout(&archive);
    }

    #[test]
    fn test_rar5_save_32mb_txt_png_pw_test() {
        let archive = check_extract(
            "rar5-save-32mb-txt-png-pw-test",
            "test",
            &[("photo.jpg", &PHOTO), ("text.txt", &TEXT)],
        );
        assert_txt_png_layout(&archive);
        assert!(archive.files[0].extra.file_encryption.is_some());
    }

    #[test]
    fn test_rar5_save_32mb_txt_png_512kb_multi_test() {
        let archive = check_extract(
            "rar5-save-32mb-txt-png-512kb.part1",
            "test",
            &[("photo.jpg", &PHOTO), ("text.txt", &TEXT)],
        );
        assert_txt_png_layout(&archive);
    }

    #[test]
    fn test_rar5_fastest_32mb_txt() {
        let a = check_extract("rar5-fastest-32mb-txt", "", &[("text.txt", &TEXT)]);
        assert_method(&a, "text.txt", CompressionFlags::Fastest);
    }

    #[test]
    fn test_rar5_fast_32mb_txt() {
        let a = check_extract("rar5-fast-32mb-txt", "", &[("text.txt", &TEXT)]);
        assert_method(&a, "text.txt", CompressionFlags::Fast);
    }

    #[test]
    fn test_rar5_normal_32mb_txt() {
        let a = check_extract("rar5-normal-32mb-txt", "", &[("text.txt", &TEXT)]);
        assert_method(&a, "text.txt", CompressionFlags::Normal);
    }

    #[test]
    fn test_rar5_good_32mb_txt() {
        let a = check_extract("rar5-good-32mb-txt", "", &[("text.txt", &TEXT)]);
        assert_method(&a, "text.txt", CompressionFlags::Good);
    }

    #[test]
    fn test_rar5_best_32mb_txt() {
        let a = check_extract("rar5-best-32mb-txt", "", &[("text.txt", &TEXT)]);
        assert_method(&a, "text.txt", CompressionFlags::Best);
    }

    #[test]
    fn test_rar5_normal_32mb_txt_png() {
        // RAR stores the jpg, the text is compressed
        let a = check_extract(
            "rar5-normal-32mb-txt-png",
            "",
            &[("photo.jpg", &PHOTO), ("text.txt", &TEXT)],
        );
        assert_method(&a, "photo.jpg", CompressionFlags::Save);
        assert_method(&a, "text.txt", CompressionFlags::Normal);
    }

    #[test]
    fn test_rar5_normal_1mb_txt_png() {
        check_extract(
            "rar5-normal-1mb-txt-png",
            "",
            &[("photo.jpg", &PHOTO), ("text.txt", &TEXT)],
        );
    }

    #[test]
    fn test_rar5_normal_32mb_txt_png_pw_test() {
        // encrypted and compressed, including the 2 MB photo
        let a = check_extract(
            "rar5-normal-32mb-txt-png-pw-test",
            "test",
            &[("photo.jpg", &PHOTO), ("text.txt", &TEXT)],
        );
        assert_method(&a, "photo.jpg", CompressionFlags::Normal);
        assert!(a.files[0].extra.file_encryption.is_some());
    }

    #[test]
    fn test_rar5_normal_32mb_txt_png_1mb_pw_multi_test() {
        // encrypted, compressed and split over three volumes
        let a = check_extract(
            "rar5-normal-32mb-txt-png-1mb-pw-test.part1",
            "test",
            &[("photo.jpg", &PHOTO), ("text.txt", &TEXT)],
        );
        assert_method(&a, "photo.jpg", CompressionFlags::Normal);
    }

    #[test]
    fn test_rar5_normal_32mb_txt_png_solid() {
        // the photo continues the solid stream of the text file
        let a = check_extract(
            "rar5-normal-32mb-txt-png-solid",
            "",
            &[("text.txt", &TEXT), ("photo.jpg", &PHOTO)],
        );
        assert!(a.files[1].compression.solid);
        assert_method(&a, "photo.jpg", CompressionFlags::Normal);
    }

    #[test]
    fn test_rar5_normal_32mb_txt_png_protect() {
        check_extract(
            "rar5-normal-32mb-txt-png-protect",
            "",
            &[("photo.jpg", &PHOTO), ("text.txt", &TEXT)],
        );
    }

    #[test]
    fn test_encrypted_compressed() {
        let expected = read_file("assets/test-encrypted-compressed.txt");
        let a = check_extract(
            "test-encrypted-compressed",
            "testpass",
            &[("test-encrypted-compressed.txt", &expected)],
        );
        assert!(a.files[0].extra.file_encryption.is_some());
        assert_method(
            &a,
            "test-encrypted-compressed.txt",
            CompressionFlags::Fastest,
        );
    }

    #[test]
    fn test_rar5_save_txt_volumes() {
        // 13 volumes, so the volume names go from part09 to part10
        let expected: Vec<(String, &[u8])> = (1..=5)
            .map(|i| (format!("text{}.txt", i), TEXT.as_slice()))
            .collect();
        let expected: Vec<(&str, &[u8])> = expected.iter().map(|(n, d)| (n.as_str(), *d)).collect();
        check_extract("rar5-save-txt-volumes.part01", "", &expected);
    }

    #[test]
    fn test_rar5_normal_dirs() {
        let out = "target/rar-test/rar5-normal-dirs/";
        let _ = remove_dir_all(out);

        let archive = Archive::extract_all("assets/rar5-normal-dirs.rar", out, "").unwrap();

        assert!(archive
            .files
            .iter()
            .any(|f| f.name == "docs" && f.flags.directory));
        assert_eq!(*TEXT, read_file(&format!("{}docs/notes/text.txt", out)));
        assert_eq!(
            read_file("assets/test-encrypted-compressed.txt"),
            read_file(&format!("{}docs/test-encrypted-compressed.txt", out))
        );
        assert!(std::path::Path::new(&format!("{}empty", out)).is_dir());

        remove_dir_all(out).unwrap();
    }

    /// Extract `archive` and expect an error. No extracted file may be left behind.
    fn extract_error(archive: &str, out: &str, password: &str) -> RarError {
        let _ = remove_dir_all(out);
        let err = Archive::extract_all(archive, out, password).unwrap_err();
        let leftovers: Vec<_> = std::fs::read_dir(out)
            .map(|dir| dir.map(|e| e.unwrap().file_name()).collect())
            .unwrap_or_default();
        assert!(leftovers.is_empty(), "left behind: {:?}", leftovers);
        let _ = remove_dir_all(out);
        err
    }

    #[test]
    fn test_wrong_password_stored() {
        let err = extract_error(
            "assets/rar5-save-32mb-txt-png-pw-test.rar",
            "target/rar-test/wrong-password-stored/",
            "wrong",
        );
        assert!(matches!(err, RarError::WrongPassword { ref filename } if filename == "photo.jpg"));
    }

    #[test]
    fn test_wrong_password_compressed() {
        let err = extract_error(
            "assets/rar5-normal-32mb-txt-png-pw-test.rar",
            "target/rar-test/wrong-password-compressed/",
            "",
        );
        assert!(matches!(err, RarError::WrongPassword { .. }));
    }

    /// Write a modified copy of an asset to `target/rar-test/`.
    fn modified_asset(name: &str, change: impl FnOnce(&mut Vec<u8>)) -> String {
        let mut data = read_file(&format!("assets/{}", name));
        change(&mut data);
        std::fs::create_dir_all("target/rar-test").unwrap();
        let path = format!("target/rar-test/{}", name);
        std::fs::write(&path, data).unwrap();
        path
    }

    #[test]
    fn test_corrupted_compressed_data() {
        // flip one byte in the middle of the compressed text
        let path = modified_asset("rar5-normal-32mb-txt.rar", |data| {
            let mid = data.len() / 2;
            data[mid] ^= 0x55;
        });
        let err = extract_error(&path, "target/rar-test/corrupted/", "");
        assert!(
            matches!(err, RarError::ChecksumMismatch { .. } | RarError::Io(_)),
            "{:?}",
            err
        );
    }

    #[test]
    fn test_corrupted_stored_data() {
        let path = modified_asset("rar5-save-32mb-txt.rar", |data| {
            let mid = data.len() / 2;
            data[mid] ^= 0x55;
        });
        let err = extract_error(&path, "target/rar-test/corrupted-stored/", "");
        assert!(
            matches!(err, RarError::ChecksumMismatch { .. }),
            "{:?}",
            err
        );
    }

    #[test]
    fn test_truncated_archive() {
        let path = modified_asset("rar5-best-32mb-txt.rar", |data| {
            data.truncate(data.len() / 2);
        });
        let err = extract_error(&path, "target/rar-test/truncated/", "");
        assert!(matches!(err, RarError::Io(_)), "{:?}", err);
    }
}
