use crypto::aessafe::AesSafe256Decryptor;
use crypto::blockmodes::{CbcDecryptor, DecPadding, NoPadding};
use crypto::buffer::{BufferResult, ReadBuffer, RefReadBuffer, RefWriteBuffer, WriteBuffer};
use crypto::hmac::Hmac;
use crypto::pbkdf2::pbkdf2;
use crypto::sha2::Sha256;
use crypto::symmetriccipher::{BlockDecryptor, Decryptor};
use std::io::{Error, ErrorKind, Read, Result, Seek, SeekFrom};

use extra::FileEncryptionBlock;
use file::File;


/// RAR Decryption reader to decrypt encrypted files
///
/// Original source-code: https://docs.rs/aes-stream/0.2.1/aesstream/
pub struct RarAesReader<R: Read> {
    /// Reader to read encrypted data from
    reader: R,
    /// Decryptor to decrypt data with
    dec: CbcDecryptor<AesSafe256Decryptor, DecPadding<NoPadding>>,
    /// Define if the encryption is active
    active: bool,
    /// Block size of BlockDecryptor, needed when seeking to correctly seek to the nearest block
    block_size: usize,
    /// Buffer used to store blob needed to find out if we reached eof
    buffer: Vec<u8>,
    /// Indicates wheather eof of the underlying buffer was reached
    eof: bool,
}

impl<R: Read> RarAesReader<R> {
    pub fn new(reader: R, file: File, pwd: &str) -> RarAesReader<R> {
        let mut key = [0u8; 32];
        let mut active = false;
        let mut feb = FileEncryptionBlock::default();
        if let Some(f) = file.extra.file_encryption {
            key = generate_key(&f, pwd);
            active = true;
            feb = f;
        }

        // define decryptor
        let aes = AesSafe256Decryptor::new(&key);
        let block_size = aes.block_size();
        let dec = CbcDecryptor::new(aes, NoPadding, feb.init.to_vec());

        RarAesReader {
            reader,
            dec,
            active,
            block_size,
            buffer: Vec::new(),
            eof: false,
        }
    }

    /// Reads at max BUFFER_SIZE bytes, handles potential eof and returns the buffer as Vec<u8>
    fn fill_buf(&mut self) -> Result<Vec<u8>> {
        let mut eof_buffer = vec![0u8; ::BUFFER_SIZE];
        let read = self.reader.read(&mut eof_buffer)?;
        self.eof = read == 0;
        eof_buffer.truncate(read);
        Ok(eof_buffer)
    }

    /// Reads and decrypts data from the underlying stream and writes it into the passed buffer.
    ///
    /// The CbcDecryptor has an internal output buffer, but not an input buffer.
    /// Therefore, we need to take care of letfover input.
    /// Additionally, we need to handle eof correctly, as CbcDecryptor needs to correctly interpret
    /// padding.
    /// Thus, we need to read 2 buffers. The first one is read as input for decryption and the second
    /// one to determine if eof is reached.
    /// The next time this function is called, the second buffer is passed as input into decryption
    /// and the first buffer is filled to find out if we reached eof.
    ///
    /// # Parameters
    ///
    /// * **buf**: Buffer to write decrypted data into.
    fn read_decrypt(&mut self, buf: &mut [u8]) -> Result<usize> {
        // if this is the first iteration, fill internal buffer
        if self.buffer.is_empty() && !self.eof {
            self.buffer = self.fill_buf()?;
        }

        let buf_len = buf.len();
        let mut write_buf = RefWriteBuffer::new(buf);
        let res;
        let remaining;
        {
            let mut read_buf = RefReadBuffer::new(&self.buffer);

            // test if CbcDecryptor still has enough decrypted data or we have enough buffered
            res = self
                .dec
                .decrypt(&mut read_buf, &mut write_buf, self.eof)
                .map_err(|e| Error::new(ErrorKind::Other, format!("decryption error: {:?}", e)))?;
            remaining = read_buf.remaining();
        }
        // keep remaining bytes
        let len = self.buffer.len();
        self.buffer.drain(..(len - remaining));
        // if we were able to decrypt, return early
        match res {
            BufferResult::BufferOverflow => return Ok(buf_len),
            BufferResult::BufferUnderflow if self.eof => return Ok(write_buf.position()),
            _ => {}
        }

        // else read new buffer
        let mut dec_len = 0;
        // We must return something, if we have something.
        // If the reader doesn't return enough so that we can decrypt a block, we need to continue
        // reading until we have enough data to return one decrypted block, or until we reach eof.
        // If we reach eof, we will be able to decrypt the final block because of padding.
        while dec_len == 0 && !self.eof {
            let eof_buffer = self.fill_buf()?;
            let remaining;
            {
                let mut read_buf = RefReadBuffer::new(&self.buffer);
                self.dec
                    .decrypt(&mut read_buf, &mut write_buf, self.eof)
                    .map_err(|e| {
                        Error::new(ErrorKind::Other, format!("decryption error: {:?}", e))
                    })?;
                let mut dec = write_buf.take_read_buffer();
                let dec = dec.take_remaining();
                dec_len = dec.len();
                remaining = read_buf.remaining();
            }
            // keep remaining bytes
            let len = self.buffer.len();
            self.buffer.drain(..(len - remaining));
            // append newly read bytes
            self.buffer.extend(eof_buffer);
        }
        Ok(dec_len)
    }
}
impl<R: Read + Seek> RarAesReader<R> {
    /// Seeks to *offset* from the start of the file
    fn seek_from_start(&mut self, offset: u64) -> Result<u64> {
        let block_num = offset / self.block_size as u64;
        let block_offset = offset % self.block_size as u64;
        // reset CbcDecryptor
        self.reader
            .seek(SeekFrom::Start((block_num - 1) * self.block_size as u64))?;
        let mut iv = vec![0u8; self.block_size];
        self.reader.read_exact(&mut iv)?;
        self.dec.reset(&iv);
        self.buffer = Vec::new();
        self.eof = false;
        let mut skip = vec![0u8; block_offset as usize];
        self.read_exact(&mut skip)?;
        // subtract IV
        Ok(offset - 16)
    }
}

impl<R: Read> Read for RarAesReader<R> {
    /// Reads encrypted data from the underlying reader, decrypts it and writes the result into the
    /// passed buffer.
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if !self.active {
            return self.reader.read(buf);
        }

        let read = self.read_decrypt(buf)?;
        Ok(read)
    }
}

impl<R: Read + Seek> Seek for RarAesReader<R> {
    /// Seek to an offset, in bytes, in a stream.
    /// [Read more](https://doc.rust-lang.org/nightly/std/io/trait.Seek.html#tymethod.seek)
    ///
    /// When seeking, this reader takes care of reinitializing the CbcDecryptor with the correct IV.
    /// The passed position does *not* need to be aligned to the blocksize.
    fn seek(&mut self, pos: SeekFrom) -> Result<u64> {
        match pos {
            SeekFrom::Start(offset) => {
                // +16 because first block is the iv
                self.seek_from_start(offset + 16)
            }
            SeekFrom::End(_) | SeekFrom::Current(_) => {
                let pos = self.reader.seek(pos)?;
                self.seek_from_start(pos)
            }
        }
    }
}

/// Generate the decryption key from the encryption block infos
fn generate_key(feb: &FileEncryptionBlock, pwd: &str) -> [u8; 32] {
    // calculate the hashing iterations
    let iter_number = 2u32.pow(feb.kdf_count.into());

    // key store
    let mut key = [0u8; 32];

    // define the hashing type and pwd
    let mut mac = Hmac::new(Sha256::new(), pwd.as_bytes());

    // hash the key
    pbkdf2(&mut mac, &feb.salt, iter_number, &mut key);

    key
}

#[test]
fn test_aes_stream_disabled() {
    let f = File::default();
    let data = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10,
    ];

    let mut reader = RarAesReader::new(&data[..], f, "");
    let mut buffer = vec![];

    reader.read_to_end(&mut buffer).unwrap();
    assert_eq!(buffer, data);
}
