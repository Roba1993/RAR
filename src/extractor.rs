use crate::aes_reader::{FileKeys, RarAesReader};
use crate::compression::{CompressionReader, SolidState};
use crate::error::{RarError, Result};
use crate::file_block::FileBlock;
use crate::file_writer::{output_path, FileWriter};
use crate::rar_reader::RarReader;
use crate::{archive_block::ArchiveBlock, sig_block::SignatureBlock};
use std::fs;
use std::io::{self, Read, Write};

/// This function extracts the data from a RarReader and writes it into an file.
///
/// `solid` carries the decompression state between the files of a solid
/// archive. It's taken for compressed files and replaced afterwards.
///
/// A file which can't be extracted completely is removed again.
pub fn extract(
    file: &FileBlock,
    path: &str,
    reader: &mut RarReader,
    data_area_size: u64,
    password: &str,
    solid: &mut Option<SolidState>,
) -> Result<()> {
    let out_path = output_path(path, &file.name)?;

    // Limit the data to take from the reader
    let mut reader = RarReader::new(reader.take(data_area_size));

    if file.flags.directory {
        fs::create_dir_all(&out_path)?;
    } else {
        let result = extract_file(file, &out_path, &mut reader, password, solid);
        if result.is_err() {
            let _ = fs::remove_file(&out_path);
        }
        result?;
    }

    // consume the rest of the data area (e.g. encryption padding)
    io::copy(&mut reader, &mut io::sink())?;
    Ok(())
}

fn extract_file(
    file: &FileBlock,
    out_path: &std::path::Path,
    reader: &mut RarReader,
    password: &str,
    solid: &mut Option<SolidState>,
) -> Result<()> {
    let wrong_password = || RarError::WrongPassword {
        filename: file.name.clone(),
    };

    // Derive the keys once; they're needed for decryption and the checksum
    let encryption = file.extra.file_encryption.as_ref();
    let keys = encryption.map(|feb| FileKeys::derive(feb, password));
    if let (Some(feb), Some(keys)) = (encryption, &keys) {
        if !keys.password_matches(feb) {
            return Err(wrong_password());
        }
    }

    let unchecked_password = encryption.is_some_and(|feb| !feb.flags.pw_check_data);

    // create file writer to create and fill the file
    let mut f_writer = FileWriter::new(file.clone(), out_path)?;

    // Chain decryption and decompression for streaming
    let aes_key = encryption
        .zip(keys.as_ref())
        .map(|(feb, k)| (k.key, feb.init));
    let aes_reader = RarAesReader::new(reader, aes_key);
    let mut comp_reader = CompressionReader::new(aes_reader, file, solid)?;

    // stop at the unpacked size, which drops the encryption padding
    let mut hasher = crc32fast::Hasher::new();
    let mut buffer = vec![0u8; 0x1_0000];
    let mut written = 0u64;
    while written < file.unpacked_size {
        let max = buffer.len().min((file.unpacked_size - written) as usize);
        let n = match comp_reader.read(&mut buffer[..max]) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            // without a password check value, a wrong password shows as corrupt data
            Err(e) if unchecked_password && e.kind() == io::ErrorKind::InvalidData => {
                return Err(wrong_password())
            }
            Err(e) => return Err(e.into()),
        };
        hasher.update(&buffer[..n]);
        f_writer.write_all(&buffer[..n])?;
        written += n as u64;
    }
    f_writer.flush()?;

    if written != file.unpacked_size {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            format!(
                "{}: extracted {} of {} bytes",
                file.name, written, file.unpacked_size
            ),
        )
        .into());
    }

    if file.flags.crc {
        let crc = hasher.finalize();
        let actual = match (encryption, &keys) {
            (Some(feb), Some(keys)) if feb.flags.tweaked_crc => keys.tweak_crc(crc),
            _ => crc,
        };
        if actual != file.data_crc {
            return Err(RarError::ChecksumMismatch {
                filename: file.name.clone(),
                expected: file.data_crc,
                actual,
            });
        }
    }

    if let Some(state) = comp_reader.into_solid_state() {
        *solid = Some(state);
    }
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
    let new_file_name =
        next_volume_name(file_name, *file_number).ok_or_else(|| RarError::FileNotFound {
            filename: format!("next volume of {}", file_name),
        })?;

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

/// The name of the volume after volume `number` (1 based) of a multi-volume
/// archive named `name.partN.rar`, keeping the zero padding of `N`.
pub(crate) fn next_volume_name(name: &str, number: usize) -> Option<String> {
    let lower = name.to_ascii_lowercase();
    let stem = lower.strip_suffix(".rar")?;
    let digits = stem.bytes().rev().take_while(u8::is_ascii_digit).count();
    let prefix = &stem[..stem.len() - digits];
    if digits == 0 || !prefix.ends_with(".part") {
        return None;
    }
    Some(format!(
        "{}{:0width$}{}",
        &name[..prefix.len()],
        number + 1,
        &name[stem.len()..],
        width = digits
    ))
}

#[test]
fn test_next_volume_name() {
    assert_eq!(next_volume_name("a.part1.rar", 1).unwrap(), "a.part2.rar");
    assert_eq!(next_volume_name("a.part9.rar", 9).unwrap(), "a.part10.rar");
    assert_eq!(
        next_volume_name("dir/a.part09.rar", 9).unwrap(),
        "dir/a.part10.rar"
    );
    assert_eq!(
        next_volume_name("a.part001.RAR", 1).unwrap(),
        "a.part002.RAR"
    );
    assert_eq!(next_volume_name("a.rar", 1), None);
    assert_eq!(next_volume_name("a1.rar", 1), None);
}
