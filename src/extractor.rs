use failure::Error;
use file;
use std;
use std::io::prelude::*;
use decryptor;

pub fn extract(file: file::File, path: &str, data: &[u8]) -> Result<(), Error> {
    let mut data = Vec::from(data);

    if file.extra.file_encryption.is_some() {
        data = decryptor::decrypt(file.clone(), &data)?;
    }

    match file.compression.flag {
        file::CompressionFlags::Save => extract_save(file, path, &data),
        _ => Err(format_err!("Can't extract this compression rate"))
    }
}



/// Save the data directly to the file
fn extract_save(file: file::File, path: &str, data: &[u8]) -> Result<(), Error> {
    std::fs::create_dir_all(path)?;
    let mut f = std::fs::File::create(format!("{}/{}", path, file.name))?;
    f.write_all(data)?;
    Ok(())
}