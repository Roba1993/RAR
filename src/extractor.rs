use failure::Error;
use file;
use std;
use std::io::prelude::*;

pub fn extract(file: file::File, path: &str, data: &[u8]) -> Result<(), Error> {
    match file.compression.flag {
        file::CompressionFlags::Save => extract_save(file, path, data),
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