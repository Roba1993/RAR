use crate::aes_reader::RarAesReader;
use crate::compression::CompressionReader;
use crate::error::{RarError, Result};
use crate::file_block::FileBlock;
use crate::file_writer::FileWriter;
use crate::rar_reader::RarReader;
use crate::{archive_block::ArchiveBlock, sig_block::SignatureBlock};
use std::io::{Read, Write};

/// This function extracts the data from a RarReader and writes it into an file.
pub fn extract(
    file: &FileBlock,
    path: &str,
    reader: &mut RarReader,
    data_area_size: u64,
    password: &str,
) -> Result<()> {
    // create file writer to create and fill the file
    let mut f_writer = FileWriter::new(file.clone(), path)?;

    // Limit the data to take from the reader
    let reader = RarReader::new(reader.take(data_area_size));

    // Initialize the decryption reader
    let aes_reader = RarAesReader::new(reader, file.clone(), password);

    // Chain AES reader directly to compression reader for true streaming
    let mut comp_reader = CompressionReader::new(aes_reader, &file.compression)?;

    // Stream with proper size limit handling
    let mut buffer = [0u8; 8192];
    loop {
        let bytes_read = comp_reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }

        let bytes_written = f_writer.write(&buffer[..bytes_read])?;
        if bytes_written == 0 {
            break; // File size limit reached
        }
    }

    f_writer.flush()?;

    Ok(())
}

/// This function chains a new .rar archive file to the data stream.
/// This ensures that we can build up a big chained reader which holds the complete
/// data_area, which then can be extracted.
pub fn continue_data_next_file<'a>(
    buffer: RarReader<'a>,
    file: &mut FileBlock,
    file_name: &str,
    file_number: &mut usize,
    data_area_size: &mut u64,
) -> Result<RarReader<'a>> {
    // get the next rar file name
    let mut new_file_name = file_name.to_string();
    let len = new_file_name.len();
    new_file_name.replace_range(len - 5.., &format!("{}.rar", *file_number + 1));

    // open the file
    let reader = ::std::fs::File::open(&new_file_name)?;

    // put the reader into our buffer
    let mut new_buffer = RarReader::new_from_file(reader);

    // try to parse the signature
    let version = new_buffer
        .exec_nom_parser(SignatureBlock::parse)
        .map_err(|_| RarError::InvalidSignature)?;
    // try to parse the archive information
    let details = new_buffer
        .exec_nom_parser(ArchiveBlock::parse)
        .map_err(|_| RarError::InvalidArchiveBlock)?;
    // try to parse the file
    let new_file = new_buffer
        .exec_nom_parser(FileBlock::parse)
        .map_err(|_| RarError::InvalidFileBlock)?;

    // check if the next file info is the same as from prvious .rar
    if version != SignatureBlock::RAR5
        || details.volume_number != *file_number as u64
        || new_file.name != file.name
    {
        return Err(RarError::FileNotFound {
            filename: "file header mismatch".to_string(),
        });
    }

    // Limit the data to take from the reader, when this data area
    // continues in another .rar archive file
    if new_file.head.flags.data_next {
        new_buffer = RarReader::new(new_buffer.take(new_file.head.data_area_size));
    }

    // count file number up
    *file_number += 1;

    // sum up the data area
    *data_area_size += new_file.head.data_area_size;

    // change the file with the new file
    *file = new_file;

    // chain the buffer together
    Ok(RarReader::new(buffer.chain(new_buffer)))
}
