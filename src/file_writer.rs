use crate::error::{RarError, Result as RarResult};
use crate::file_block::FileBlock;
use std::fs;
use std::io::{BufWriter, Result, Write};
use std::path::{Path, PathBuf};

/// The location of the archive entry `name` below the directory `dir`.
///
/// Names which are absolute or contain `..` are rejected, so an archive
/// can't write outside of `dir`.
pub fn output_path(dir: &str, name: &str) -> RarResult<PathBuf> {
    let unsafe_name = || RarError::UnsafeFileName {
        filename: name.to_string(),
    };
    // RAR5 uses '/' as separator; '\\' and drive letters are checked as
    // well, because they're special on Windows.
    let drive =
        name.len() >= 2 && name.as_bytes()[1] == b':' && name.as_bytes()[0].is_ascii_alphabetic();
    if name.starts_with(['/', '\\']) || drive {
        return Err(unsafe_name());
    }
    let mut path = PathBuf::from(dir);
    for part in name.split(['/', '\\']) {
        match part {
            "" | "." => {}
            ".." => return Err(unsafe_name()),
            part => path.push(part),
        }
    }
    if path == Path::new(dir) {
        return Err(unsafe_name());
    }
    Ok(path)
}

/// This FileWriter writes out the data into a new
/// file underneath the given path
pub struct FileWriter {
    file: FileBlock,
    writer: BufWriter<fs::File>,
    bytes_written: u64,
}

impl FileWriter {
    /// Create the file `path` (and its parent directories) for `file`.
    pub fn new(file: FileBlock, path: &Path) -> Result<FileWriter> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        // create a file writer with a buffer
        let writer = BufWriter::new(fs::File::create(path)?);

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
    use crate::file_writer::{output_path, FileWriter};
    use std::fs::{remove_dir_all, File};
    use std::io::{ErrorKind, Read, Write};
    use std::path::PathBuf;

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
            let path = output_path("target/rar-test/file_writer/", &file.name).unwrap();
            let mut fw = FileWriter::new(file, &path).unwrap();
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

    #[test]
    fn test_output_path() {
        assert_eq!(
            output_path("out", "dir/sub/file.txt").unwrap(),
            PathBuf::from("out/dir/sub/file.txt")
        );
        assert_eq!(
            output_path("out", "./a//b").unwrap(),
            PathBuf::from("out/a/b")
        );
        assert_eq!(
            output_path("out", "10:30.txt").unwrap(),
            PathBuf::from("out/10:30.txt")
        );
        for name in [
            "../x",
            "a/../../x",
            "/etc/passwd",
            "\\x",
            "C:x",
            "a\\..\\..\\x",
            "",
            ".",
        ] {
            assert!(output_path("out", name).is_err(), "{:?}", name);
        }
    }
}
