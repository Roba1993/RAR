#[macro_use]
extern crate failure;
#[macro_use]
extern crate nom;
#[macro_use]
extern crate lazy_static;
extern crate chrono;
extern crate crypto;

mod archive;
mod buffer;
mod decryption_reader;
mod end;
mod extra;
mod extractor;
mod file;
mod file_writer;
mod header;
mod signature;
mod util;
mod vint;

const BUFFER_SIZE: usize = 8192;

use failure::Error;
use std::fs::File;
use std::io::{Read, Seek};

/// The rar archive representation
#[derive(PartialEq, Debug)]
pub struct Archive {
    pub file_name: String,
    pub version: signature::RarSignature,
    pub details: archive::ArchiveBlock,
    pub files: Vec<file::File>,
    pub quick_open: Option<file::File>,
    pub end: end::EndBlock,
}

impl Archive {
    /// Opens an .rar file and tries to parse it's content.
    /// This function returns an Archive with all the detailed information
    /// about the .rar file.
    pub fn open<F: Into<String>>(file_name: F) -> Result<Archive, Error> {
        Archive::handle(file_name, ExtractionOption::ExtractNone, "")
    }

    /// Extract all files of the .rar archive
    pub fn extract_all<F: Into<String>>(file_name: F, path: &str) -> Result<Archive, Error> {
        Archive::handle(file_name, ExtractionOption::ExtractAll, path)
    }

    /// Just parse all the rar information header
    pub fn parse<F: Into<String>>(file_name: F, path: &str) -> Result<Archive, Error> {
        Archive::handle(file_name, ExtractionOption::ExtractNone, path)
    }

    /// Function to handle the .rar file in detail.
    /// Most of the other functions available are
    /// easy to use abstraction of this function.
    pub fn handle<F: Into<String>>(
        file_name: F,
        ext: ExtractionOption,
        path: &str,
    ) -> Result<Archive, Error> {
        let file_name = file_name.into();
        // Open a file reader
        let reader = File::open(&file_name)?;
        // initilize the buffer
        let mut buffer = buffer::DataBuffer::new_from_file(reader);

        // try to parse the signature
        let version = buffer
            .exec_nom_parser(signature::RarSignature::parse)
            .map_err(|_| format_err!("Can't read RAR signature"))?;
        // try to parse the archive information
        let details = buffer
            .exec_nom_parser(archive::archive)
            .map_err(|_| format_err!("Can't read RAR archive block"))?;

        let mut files = vec![];
        let mut quick_open = None;
        // loop over the packages and define how to handle them
        loop {
            // Check if it is a file
            match buffer.exec_nom_parser(file::file) {
                Ok(mut f) => {
                    // quick open file?
                    if f.name == "QO" {
                        buffer.seek(f.head.data_area_size)?;
                        quick_open = Some(f);
                        break;
                    }

                    /*let mut file_number = 0;
                    while f.head.flags.data_next {
                        let b = ::extractor::continue_data_next_file(
                            buffer,
                            &mut f,
                            &file_name,
                            file_number,
                        )?;
                        buffer = buffer::DataBuffer::new(b);
                        file_number += 1;
                    }*/

                    // extract the file?
                    if ext == ExtractionOption::ExtractAll
                        || ext == ExtractionOption::ExtractFile(f.name.clone())
                    {
                        extractor::extract(&f, path, &file_name, &mut buffer)?;
                    } else {
                        buffer.seek(f.head.data_area_size)?;
                    }

                    // add the file to the array
                    files.push(f);
                }
                Err(_) => {
                    break;
                }
            }
        }

        // Get the end block
        let end = buffer
            .exec_nom_parser(end::end_block)
            .map_err(|_| format_err!("Can't read RAR end"))?;

        Ok(Archive {
            file_name,
            version,
            details,
            files,
            quick_open,
            end,
        })
    }
}

/// The different extraction options for the .rar file
#[derive(PartialEq, Debug)]
pub enum ExtractionOption {
    ExtractNone,
    ExtractAll,
    ExtractFile(String),
}

#[cfg(test)]
mod tests {
    use signature;
    use std::fs::{remove_dir_all, File};
    use std::io::Read;
    use Archive;

    // Small helper function to read a file
    fn read_file(path: &str) -> Vec<u8> {
        let mut data = vec![];
        let mut file = File::open(path).unwrap();
        file.read_to_end(&mut data).unwrap();
        data
    }

    // Get the photo globally so that every test can compare it
    lazy_static! {
        static ref PHOTO: Vec<u8> = { read_file("assets/photo.jpg") };
    }

    // Get the photo globally so that every test can compare it
    lazy_static! {
        static ref TEXT: Vec<u8> = { read_file("assets/text.txt") };
    }

    #[test]
    fn test_rar5_save_32mb_txt() {
        let rar = "rar5-save-32mb-txt";

        let archive = Archive::extract_all(
            format!("assets/{}.rar", rar),
            &format!("target/rar-test/{}/", rar),
        ).unwrap();

        assert_eq!(archive.version, signature::RarSignature::RAR5);
        assert_eq!(archive.files[0].name, "text.txt");
        assert_eq!(archive.files[0].unpacked_size, 2118);
        assert_eq!(
            *TEXT,
            read_file(&format!("target/rar-test/{}/text.txt", rar))
        );

        remove_dir_all(&format!("target/rar-test/{}", rar)).unwrap();
    }

    #[test]
    fn test_rar5_save_32mb_txt_png() {
        let archive = Archive::extract_all(
            "assets/rar5-save-32mb-txt-png.rar",
            "target/rar-test/rar5-save-32mb-txt-png/",
        ).unwrap();

        assert_eq!(archive.version, signature::RarSignature::RAR5);
        assert_eq!(archive.files[0].name, "photo.jpg");
        assert_eq!(archive.files[0].unpacked_size, 2149083);
        assert_eq!(archive.files[1].name, "text.txt");
        assert_eq!(archive.files[1].unpacked_size, 2118);
        assert_eq!(archive.quick_open.unwrap().name, "QO");
        assert_eq!(
            *TEXT,
            read_file("target/rar-test/rar5-save-32mb-txt-png/text.txt")
        );
        assert_eq!(
            *PHOTO,
            read_file("target/rar-test/rar5-save-32mb-txt-png/photo.jpg")
        );

        remove_dir_all("target/rar-test/rar5-save-32mb-txt-png/").unwrap();
    }

    #[test]
    fn test_rar5_save_32mb_txt_png_read_only() {
        let archive = Archive::parse(
            "assets/rar5-save-32mb-txt-png.rar",
            "target/rar-test/rar5-save-32mb-txt-png/",
        ).unwrap();

        assert_eq!(archive.version, signature::RarSignature::RAR5);
        assert_eq!(archive.files[0].name, "photo.jpg");
        assert_eq!(archive.files[0].unpacked_size, 2149083);
        assert_eq!(archive.files[1].name, "text.txt");
        assert_eq!(archive.files[1].unpacked_size, 2118);
        assert_eq!(archive.quick_open.unwrap().name, "QO");
    }

    #[test]
    // this test takes a while right now
    #[ignore]
    fn test_rar5_save_32mb_txt_png_pw_test_3() {
        let archive = Archive::extract_all(
            "assets/rar5-save-32mb-txt-png-pw-test.rar",
            "target/rar-test/rar5-save-32mb-txt-png-pw-test/",
        ).unwrap();

        assert_eq!(archive.version, signature::RarSignature::RAR5);
        assert_eq!(archive.files[0].name, "photo.jpg");
        assert_eq!(archive.files[0].unpacked_size, 2149083);
        assert_eq!(archive.files[1].name, "text.txt");
        assert_eq!(archive.files[1].unpacked_size, 2118);
        assert_eq!(archive.quick_open.unwrap().name, "QO");
        assert_eq!(
            *TEXT,
            read_file("target/rar-test/rar5-save-32mb-txt-png-pw-test/text.txt")
        );
        assert_eq!(
            *PHOTO,
            read_file("target/rar-test/rar5-save-32mb-txt-png-pw-test/photo.jpg")
        );

        remove_dir_all("target/rar-test/rar5-save-32mb-txt-png-pw-test/").unwrap();
    }

    #[test]
    #[ignore]
    fn test_rar5_save_32mb_txt_png_512kb_multi_test() {
        let archive = Archive::parse(
            "assets/rar5-save-32mb-txt-png-512kb.part1.rar",
            "target/rar-test/rar5-normal-32mb-txt-png-1mb-pw-test/",
        ).unwrap();

        println!("{:?}", archive);

        let archive = Archive::parse(
            "assets/rar5-save-32mb-txt-png-512kb.part2.rar",
            "target/rar-test/rar5-normal-32mb-txt-png-1mb-pw-test/",
        ).unwrap();

        println!("\n{:?}", archive);

        assert!(false);
    }
}
