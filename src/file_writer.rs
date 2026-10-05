use crate::file_block::FileBlock;
use std::fs;
use std::io::{BufWriter, Result, Write};

/// This FileWriter writes out the data into a new
/// file underneath the given path
pub struct FileWriter {
    file: FileBlock,
    writer: BufWriter<fs::File>,
    bytes_written: u64,
}

impl FileWriter {
    /// Create a new FileWriter to write the data
    pub fn new(file: FileBlock, path: &str) -> Result<FileWriter> {
        // create the file and the path
        fs::create_dir_all(path)?;

        // create a file writer with a buffer
        let writer = BufWriter::new(fs::File::create(format!("{}/{}", path, file.name))?);

        // return the FileWriter
        Ok(FileWriter {
            file,
            writer,
            bytes_written: 0,
        })
    }
}

impl Write for FileWriter {
    /// Write the data into the file
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        // calculate the length which still needs to be written
        let mut len = (self.file.unpacked_size - self.bytes_written) as usize;

        // when no data needs to be written anymore return 0
        if len == 0 {
            return Ok(0);
        }

        // when the buffer is smaller than the need to write shrink to buffer size
        if len > buf.len() {
            len = buf.len();
        }

        self.writer.write_all(&buf[..len])?;
        self.bytes_written += len as u64;
        Ok(len)
    }

    fn flush(&mut self) -> Result<()> {
        self.writer.flush()
    }
}

#[cfg(test)]
mod tests {
    use crate::file_block::FileBlock;
    use crate::file_writer::FileWriter;
    use std::fs::{remove_dir_all, File};
    use std::io::{ErrorKind, Read, Write};

    // Small helper function to read a file
    fn read_file(path: &str) -> Vec<u8> {
        let mut data = vec![];
        let mut file = File::open(path).unwrap();
        file.read_to_end(&mut data).unwrap();
        data
    }

    #[test]
    fn test_file_writer() {
        let file = FileBlock {
            unpacked_size: 10,
            name: "test.txt".to_string(),
            ..Default::default()
        };

        let data = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13,
            0x14,
        ];

        {
            let mut fw = FileWriter::new(file, "target/rar-test/file_writer/").unwrap();
            assert_eq!(
                fw.write_all(&data).map_err(|e| e.kind()),
                Err(ErrorKind::WriteZero)
            );
            fw.flush().unwrap();
        }

        assert_eq!(
            read_file("target/rar-test/file_writer/test.txt"),
            data[..10].to_vec()
        );

        remove_dir_all("target/rar-test/file_writer/").unwrap();
    }
}
