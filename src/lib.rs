#[macro_use] extern crate failure;
#[macro_use] extern crate nom;

mod util;
mod vint;
mod signature;
mod header;
mod archive;
mod file;
mod end;
mod extractor;

use std::io::Read;
use failure::Error;

/// The rar archive representation
#[derive(PartialEq, Debug)]
pub struct Archive {
    pub version: signature::RarSignature,
    pub details: archive::ArchiveBlock,
    pub files: Vec<file::File>,
    pub quick_open: Option<file::File>,
    pub end: end::EndBlock
}

impl Archive {
    /// Opens an .rar file and tries to parse it's content.
    /// This function returns an Archive with all the detailed information
    /// about the .rar file.
    pub fn open<R: Read>(reader: &mut R) -> Result<Archive, Error> {
        Archive::handle(reader, ExtractionOption::ExtractNone, "")
    }

    /// Extract all files of the .rar archive
    pub fn extract_all<R: Read>(reader: &mut R, path: &str) -> Result<Archive, Error> {
        Archive::handle(reader, ExtractionOption::ExtractAll, path)
    }

    /// Function to handle the .rar file in detail.
    /// Most of the other functions available are 
    /// easy to use abstraction of this function.
    pub fn handle<R: Read>(reader: &mut R, ext: ExtractionOption, path: &str) -> Result<Archive, Error> {
        // initilize the buffer
        let mut buffer = vec!();
        reader.read_to_end(&mut buffer)?;
        

        // try to parse the signature
        let (input, version) = signature::RarSignature::parse(&buffer).map_err(|_| format_err!("Can't read RAR signature"))?;
    
        // try to parse the archive information
        let (mut input, details) = archive::archive(input).map_err(|_| format_err!("Can't read RAR archive"))?;

        let mut files = vec!();
        let mut quick_open = None;
        // loop over the packages and define how to handle them
        loop {
            // Check if it is a file
            match file::file(input) {
                Ok((i, f)) => {
                    // quick open file?
                    if f.name == "QO" {
                        input = &i[(f.unpacked_size as usize)..];
                        quick_open = Some(f);
                        break;
                    }

                    // extract the file?
                    if ext == ExtractionOption::ExtractAll || ext == ExtractionOption::ExtractFile(f.name.clone()) {
                        extractor::extract(f.clone(), path, &i[(.. f.unpacked_size as usize)])?;
                    }

                    // push the curser foreward and the file to the array
                    input = &i[(f.unpacked_size as usize)..];
                    files.push(f);
                },
                Err(_) => {
                    break;
                }
            }
        }
        
        // Get the end block
        let (_, end) = end::end_block(input).map_err(|_| format_err!("Can't read RAR end"))?;

        Ok(Archive {
            version,
            details,
            files,
            quick_open,
            end
        })
    }
}

/// The different extraction options for the .rar file
#[derive(PartialEq, Debug)]
pub enum ExtractionOption {
    ExtractNone,
    ExtractAll,
    ExtractFile(String)
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use ::Archive;
    use ::signature;

    #[test]
    fn test_rar5_save_32mb_txt() {
        let mut file = File::open("assets/rar5-save-32mb-txt.rar").unwrap();
        let archive = Archive::open(&mut file).unwrap();
        
        assert_eq!(archive.version, signature::RarSignature::RAR5);
        assert_eq!(archive.files[0].name, "text.txt");
        assert_eq!(archive.files[0].unpacked_size, 2118);
    }

    #[test]
    fn test_rar5_save_32mb_txt_png() {
        let mut file = File::open("assets/rar5-save-32mb-txt-png.rar").unwrap();
        let archive = Archive::open(&mut file).unwrap();

        assert_eq!(archive.version, signature::RarSignature::RAR5);
        assert_eq!(archive.files[0].name, "photo.jpg");
        assert_eq!(archive.files[0].unpacked_size, 2149083);
        assert_eq!(archive.files[1].name, "text.txt");
        assert_eq!(archive.files[1].unpacked_size, 2118);
        assert_eq!(archive.quick_open.unwrap().name, "QO");
    }
}
