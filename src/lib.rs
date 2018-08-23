#[macro_use] extern crate failure;
#[macro_use] extern crate nom;

mod util;
mod vint;
mod signature;
mod header;
mod archive;
mod file;

use std::io::Read;
use failure::Error;

/// The rar archive representation
#[derive(PartialEq, Debug)]
pub struct Archive {
    pub version: signature::RarSignature,
    pub details: archive::ArchiveBlock,
    pub files: Vec<file::File>,
}

impl Archive {
    pub fn open<R: Read>(reader: &mut R) -> Result<Archive, Error> {
        // initilize the buffer
        let mut buffer = vec!();
        reader.read_to_end(&mut buffer)?;
        

        // try to parse the signature
        let (input, version) = signature::RarSignature::parse(&buffer).map_err(|_| format_err!("Can't read RAR signature"))?;
    
        // try to parse the archive information
        let (mut input, details) = archive::archive(input).map_err(|_| format_err!("Can't read RAR archive"))?;

        // get all files for this container
        let mut files = vec!();

        loop {
            match file::file(input) {
                Ok((i, f)) => {
                    input = &i[(f.unpacked_size as usize)..];
                    files.push(f);
                },
                Err(_) => {
                    break;
                }
            }
        }
        


        Ok(Archive {
            version,
            details,
            files,
        })
    }
}

/// File representation from a rar archive
pub struct File {
    pub name: String,
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
    }
}
