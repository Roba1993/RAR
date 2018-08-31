use failure;
use nom;
use std::io;
use std::io::{BufRead, BufReader, Read};

/// The RarReader is abstracting an BufRead trait to 
/// easily share, change and chain the different reader.
/// 
/// In addition it provides and r_seek and nom parser functionality.
pub struct RarReader<'a> {
    inner: Box<BufRead + 'a>,
}


impl<'a> RarReader<'a>{
    /// Create a new RarReader based upon an anlready existing
    /// BufRead implementation
    pub fn new<R: BufRead + 'a>(r: R) -> RarReader<'a> {
        RarReader {
            inner: Box::new(r),
        }
    }

    /// Create a new RarReader implementation over an file.
    /// Internally we creating an BufReader to accelerrate the performance.
    pub fn new_from_file(file: ::std::fs::File) -> RarReader<'a> {
        RarReader {
            inner: Box::new(BufReader::new(file)),
        }
    }

    /// Seeks the reader forward -> right now it's leveraging the read function
    /// which is not really performant....
    /// 
    /// Unless the Chain struct is not supporting the Seek trait, we need to live with this.
    pub fn r_seek(&mut self, amt: u64) -> Result<(), io::Error> {
        let mut amt = amt;
        let mut buf = [0u8; 8000];

        // continue as long as we haven't seeked enough
        while amt > 0 {
            let mut len = buf.len();

            // when the buffer is bigger than the need to seek
            // we shrink the buffer. Otherwiese we would seek to much.
            if buf.len() > amt as usize {
                len = amt as usize;
            }

            // read the data to pusht he curser foreward
            self.inner.read_exact(&mut buf[..len])?;
            // subtract the readed data
            amt -= len as u64;
        }

        Ok(())
    }

    /// This function executes a nom parser against the data of the buffer.
    pub fn exec_nom_parser<F, D>(&mut self, func: F) -> Result<D, failure::Error>
    where
        F: Fn(&[u8]) -> nom::IResult<&[u8], D>
    {
        // Local enum for collecting the stati and avoid locks between
        // using the inner bufreader
        enum Stati<D> {
            Error,
            Success(usize, D),
        }

        // execute the nom command against the buffer content
        // and match the outcome to the local stati enum
        let res;
        let buf_len;
        {
            let buf = self.fill_buf()?;
            buf_len = buf.len();
            match func(buf) {
                Ok((bl, d)) => {
                    res = Stati::Success(bl.len(), d);
                }
                Err(_) => {
                    res = Stati::Error;
                }
            }
        }

        // take the outcome and perform the required changes
        match res {
            // on error return an error
            Stati::Error => Err(format_err!("Can't execute nom parser")),
            // on sucess resize the buffer and return the result
            Stati::Success(bl, d) => {
                self.consume(buf_len - bl);
                Ok(d)
            }
        }
    }
}

impl<'a> Read for RarReader<'a> {
    /// Read from the internal reader.
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        self.inner.read(buf)
    }

}

impl<'a> BufRead for RarReader<'a> {
    /// Fills the buffer and returns the content
    fn fill_buf(&mut self) -> Result<&[u8], io::Error> {
        self.inner.fill_buf()
    }

    /// Tells this buffer that amt bytes have been consumed from the buffer, 
    /// so they should no longer be returned in calls to read.
    /// 
    /// Only the buffer is effected, can't push more foreward than the buffer
    fn consume(&mut self, amt: usize) {
        self.inner.consume(amt)
    }
}

#[test]
fn test_exec_nom_parser() {
    let data = [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00, 0xFF, 0xFF, 0xFF];

    let mut db = RarReader::new(::std::io::Cursor::new(data));

    assert!(db.exec_nom_parser(::sig_block::SignatureBlock::parse).is_ok());
    assert_eq!(db.fill_buf().unwrap(), &data[8..]);
}
#[test]
fn test_consume() {
    let data = [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00, 0xFF, 0xFF, 0xFF];

    let mut db = RarReader::new(::std::io::Cursor::new(data));

    db.consume(8);
    assert_eq!(db.fill_buf().unwrap(), &data[8..]);
}
#[test]
fn test_seek() {
    let data = [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00, 0xFF, 0xFF, 0xFF];

    let mut db = RarReader::new(::std::io::Cursor::new(data));

    db.consume(8);
    assert_eq!(db.fill_buf().unwrap(), &data[8..]);
}