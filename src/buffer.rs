use failure;
use nom;
use std::io;
use std::io::{BufRead, BufReader, Read, Seek};

pub struct DataBuffer<R> {
    inner: BufReader<R>,
}

impl<R: Read + Seek> DataBuffer<R> {
    pub fn new(r: R) -> DataBuffer<R> {
        DataBuffer {
            inner: BufReader::new(r),
        }
    }

    /// Gets a reference to the underlying reader.
    /// It is inadvisable to directly read from the underlying reader.
    pub fn get_ref(&mut self) -> &mut BufReader<R> {
        &mut self.inner
    }

    /// Returns a reference to the internally buffered data.
    /// Unlike fill_buf, this will not attempt to fill the buffer if it is empty.
    pub fn buffer(&self) -> &[u8] {
        self.inner.buffer()
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
            Incomplete,
            Success(usize, D),
        }

        // execute the nom command against the buffer content
        // and match the outcome to the local stati enum
        let res;
        match func(self.inner.buffer()) {
            Ok((bl, d)) => {
                res = Stati::Success(bl.len(), d);
            }
            Err(e) => match e {
                nom::Err::Incomplete(_) => {
                    res = Stati::Incomplete;
                }
                _ => {
                    res = Stati::Error;
                }
            },
        }

        // based upon the local stati, perform the right action
        match res {
            // on error return an error
            Stati::Error => Err(format_err!("Can't execute nom parser")),
            // on incomplete, refill the buffer and try again
            Stati::Incomplete => {
                self.inner.fill_buf()?;
                self.exec_nom_parser(func)
            }
            // on sucess resize the buffer and return the result
            Stati::Success(bl, d) => {
                let l = self.inner.buffer().len();
                self.inner.consume(l - bl);
                Ok(d)
            }
        }
    }
}

impl<R: Read> Read for DataBuffer<R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        self.inner.read(buf)
    }
}

#[test]
fn test_exec_nom_parser() {
    let data = [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00, 0xFF, 0xFF, 0xFF];

    let mut db = DataBuffer::new(::std::io::Cursor::new(data));

    assert!(db.exec_nom_parser(::signature::RarSignature::parse).is_ok());
    assert_eq!(db.buffer(), &data[8..]);
}