use buffer::DataBuffer;
use decryption_reader::RarAesReader;
use failure::Error;
use file;
use file_writer::FileWriter;
use std::io::prelude::*;
use std::io::{Read, Seek, Chain};

pub fn extract(
    file: &file::File,
    path: &str,
    file_name: &str,
    buffer: &mut DataBuffer,
) -> Result<(), Error> {
    // create file writer to create and fill the file
    let mut f_writer = FileWriter::new(file.clone(), &path)?;

    // Limit the data to take from the reader
    let mut buffer = buffer.take(file.head.data_area_size);

    // Initilize the decryption reader
    let mut buffer = RarAesReader::new(&mut buffer, file.clone(), "test");

    // loop over chunks of the data and write it to the files
    let mut file_number = 0;
    let mut data_buffer = [0u8; ::BUFFER_SIZE];
    loop {
        // read a chunk of data from the buffer
        let new_byte_count = buffer.read(&mut data_buffer)?;
        let data = &mut data_buffer[..new_byte_count];

        // end loop if nothing is there anymore
        if new_byte_count <= 0 && !file.head.flags.data_next {
            break;
        }
        // read next file when a second part is available
        else if new_byte_count <= 0 && file.head.flags.data_next {
            file_number += 1;
        }

        // unpack if necessary
        // todo

        // write out the data
        if let Err(e) = f_writer.write_all(&data) {
            if e.kind() == ::std::io::ErrorKind::WriteZero {
                // end loop when the file capacity is reached
                break;
            } else {
                Err(e)?;
            }
        }
    }

    // flush the data
    f_writer.flush()?;

    Ok(())
}

/*pub fn continue_data_next_file<'a, D: Read + 'a>(
    buffer: D,
    file: &mut file::File,
    file_name: &str,
    file_number: usize,
) -> Result<Box<Read + 'a>, Error> {
    // get the next rar file name
    let mut new_file_name = file_name.to_string();
    new_file_name.replace_range(..file_name.len() - 5, &format!("{}.rar", file_number + 1));

    // open the file
    let mut reader = ::std::fs::File::open(new_file_name)?;

    // put the reader into our buffer
    let mut new_buffer = DataBuffer::new(reader);

    // try to parse the signature
    let version = new_buffer
        .exec_nom_parser(::signature::RarSignature::parse)
        .map_err(|_| format_err!("Can't read RAR signature"))?;
    // try to parse the archive information
    let details = new_buffer
        .exec_nom_parser(::archive::archive)
        .map_err(|_| format_err!("Can't read RAR archive block"))?;
    // try to parse the file
    let new_file = new_buffer
        .exec_nom_parser(file::file)
        .map_err(|_| format_err!("Can't read RAR file block"))?;

    if version != ::signature::RarSignature::RAR5
        || details.volume_number != file_number as u64
        || new_file.name != file.name
    {
        return Err(format_err!("The file header in the new .rar file don't match the needed file"));
    }

    // Limit the data to take from the reader
    let mut new_buffer = new_buffer.take(new_file.head.data_area_size);

    // change the file with the new file
    *file = new_file;

    // chain the buffer together
    Ok(Box::new(buffer.chain(new_buffer)) as Box<Read>)
}
*/