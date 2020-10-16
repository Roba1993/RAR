#[macro_use]
extern crate failure;
#[macro_use]
extern crate nom;
extern crate chrono;
extern crate crypto;

#[cfg(test)]
#[macro_use]
extern crate lazy_static;

mod aes_reader;
mod archive_block;
mod end_block;
mod extra_block;
mod extractor;
mod file_block;
mod file_writer;
mod head_block;
mod rar_reader;
mod sig_block;
mod util;
mod vint;

const BUFFER_SIZE: usize = 8192;

use failure::Error;
use rar_reader::RarReader;
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
    pub fn extract_all(file_name: &str, path: &str, password: &str) -> Result<Archive, Error> {
        // Open a file reader
        let reader = File::open(&file_name)?;
        // initilize the buffer
        let mut reader = RarReader::new_from_file(reader);

        // try to parse the signature
        let version = reader
            .exec_nom_parser(sig_block::SignatureBlock::parse)
            .map_err(|_| format_err!("Can't read RAR signature"))?;
        // try to parse the archive information
        let details = reader
            .exec_nom_parser(archive_block::ArchiveBlock::parse)
            .map_err(|_| format_err!("Can't read RAR archive block"))?;

        let mut files = vec![];
        let mut quick_open = None;
        let mut file_number = 1;
        // loop over the packages and define how to handle them
        loop {
            // Check if the next is a file
            match reader.exec_nom_parser(file_block::FileBlock::parse) {
                Ok(mut f) => {
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
                            &file_name,
                            &mut file_number,
                            &mut data_area_size,
                        )?;
                    }

                    // extract all the data
                    extractor::extract(&f, path, &mut reader, data_area_size, password)?;

                    // add the file to the array
                    files.push(f);
                }
                Err(_) => {
                    break;
                }
            }
        }

        // Get the end block
        let end = reader
            .exec_nom_parser(end_block::EndBlock::parse)
            .map_err(|_| format_err!("Can't read RAR end"))?;

        // return the archive information
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
    use sig_block::SignatureBlock;
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
        static ref PHOTO: Vec<u8> = read_file("assets/photo.jpg");
    }

    // Get the photo globally so that every test can compare it
    lazy_static! {
        static ref TEXT: Vec<u8> = read_file("assets/text.txt");
    }

    #[test]
    fn test_rar5_save_32mb_txt() {
        let rar = "rar5-save-32mb-txt";

        let archive = Archive::extract_all(
            &format!("assets/{}.rar", rar),
            &format!("target/rar-test/{}/", rar),
            "test",
        )
        .unwrap();

        assert_eq!(archive.version, SignatureBlock::RAR5);
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
            "test",
        )
        .unwrap();

        assert_eq!(archive.version, SignatureBlock::RAR5);
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
    fn test_rar5_save_32mb_txt_png_pw_test() {
        let archive = Archive::extract_all(
            "assets/rar5-save-32mb-txt-png-pw-test.rar",
            "target/rar-test/rar5-save-32mb-txt-png-pw-test/",
            "test",
        )
        .unwrap();

        assert_eq!(archive.version, SignatureBlock::RAR5);
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
    fn test_rar5_save_32mb_txt_png_512kb_multi_test() {
        let archive = Archive::extract_all(
            "assets/rar5-save-32mb-txt-png-512kb.part1.rar",
            "target/rar-test/rar5-save-32mb-txt-png-512kb/",
            "test",
        )
        .unwrap();

        assert_eq!(archive.version, SignatureBlock::RAR5);
        assert_eq!(archive.files[0].name, "photo.jpg");
        assert_eq!(archive.files[0].unpacked_size, 2149083);
        assert_eq!(archive.files[1].name, "text.txt");
        assert_eq!(archive.files[1].unpacked_size, 2118);
        assert_eq!(archive.quick_open.unwrap().name, "QO");
        assert_eq!(
            *PHOTO,
            read_file("target/rar-test/rar5-save-32mb-txt-png-512kb/photo.jpg")
        );
        assert_eq!(
            *TEXT,
            read_file("target/rar-test/rar5-save-32mb-txt-png-512kb/text.txt")
        );

        remove_dir_all("target/rar-test/rar5-save-32mb-txt-png-512kb/").unwrap();
    }
}
