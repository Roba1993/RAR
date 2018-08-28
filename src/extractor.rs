use buffer::DataBuffer;
use decryption_reader::RarAesReader;
use failure::Error;
use file;
use file_writer::FileWriter;
use std::io::prelude::*;
use std::io::{Read, Seek};

pub fn extract<D: Read + Seek>(
    file: &file::File,
    path: &str,
    buffer: &mut DataBuffer<D>,
) -> Result<(), Error> {
    // create file writer to create and fill the file
    let mut f_writer = FileWriter::new(file.clone(), &path)?;

    // Limit the data to take from the reader
    let mut buffer = buffer.take(file.head.data_area_size);

    // Initilize the decryption reader
    let mut buffer = RarAesReader::new(&mut buffer, file.clone(), "test");

    // loop over chunks of the data and write it to the files
    let mut data_buffer = [0u8; 4096];
    loop {
        // read a chunk of data from the buffer
        let new_byte_count = buffer.read(&mut data_buffer)?;
        let data = &mut data_buffer[..new_byte_count];

        // end loop if nothing is there anymore
        if new_byte_count <= 0 {
            break;
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
