use buffer::DataBuffer;
use decryption_reader::RarAesReader;
use failure::Error;
use file;
use file_writer::FileWriter;
use std::io::prelude::*;
use std::io::Read;

pub fn extract(file: &file::File, path: &str, buffer: &mut DataBuffer, data_area_size: u64, password: &str) -> Result<(), Error> {
    // create file writer to create and fill the file
    let mut f_writer = FileWriter::new(file.clone(), &path)?;

    // Limit the data to take from the reader
    let buffer = DataBuffer::new(buffer.take(data_area_size));

    // Initilize the decryption reader
    let mut buffer = RarAesReader::new(buffer, file.clone(), password);

    // loop over chunks of the data and write it to the files
    let mut data_buffer = [0u8; ::BUFFER_SIZE];
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

pub fn continue_data_next_file<'a>(
    buffer: DataBuffer<'a>,
    file: &mut file::File,
    file_name: &str,
    file_number: &mut usize,
    data_area_size: &mut u64,
) -> Result<DataBuffer<'a>, Error> {
    // get the next rar file name
    let mut new_file_name = file_name.to_string();
    let len = new_file_name.len();
    new_file_name.replace_range(len - 5.., &format!("{}.rar", *file_number + 1));

    // open the file
    let reader = ::std::fs::File::open(&new_file_name)?;

    // put the reader into our buffer
    let mut new_buffer = DataBuffer::new_from_file(reader);

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

    // check if the next file info is the same as from prvious .rar
    if version != ::signature::RarSignature::RAR5
        || details.volume_number != *file_number as u64
        || new_file.name != file.name
    {
        return Err(format_err!(
            "The file header in the new .rar file don't match the needed file"
        ));
    }

    // Limit the data to take from the reader, when files are following
    if new_file.head.flags.data_next {
        new_buffer = DataBuffer::new(new_buffer.take(new_file.head.data_area_size));
    }

    // count file number up
    *file_number += 1;

    // sum up the data area
    *data_area_size += new_file.head.data_area_size;

    // change the file with the new file
    *file = new_file;

    // chain the buffer together
    Ok(DataBuffer::new(buffer.chain(new_buffer)))
}
