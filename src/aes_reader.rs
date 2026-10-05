use aes::Aes256;
use cbc::cipher::{block_padding::NoPadding, BlockModeDecrypt, KeyIvInit};
use hmac::Hmac;
use pbkdf2::pbkdf2;
use sha2::Sha256;
use std::io::{Read, Result, Seek, SeekFrom};

use crate::extra_block::FileEncryptionBlock;
use crate::file_block::FileBlock;

type Aes256CbcDec = cbc::Decryptor<Aes256>;

/// RAR Decryption reader to decrypt .rar archive files
pub struct RarAesReader<R: Read> {
    reader: R,
    active: bool,
    buffer: Vec<u8>,
    buffer_pos: usize,
    key: [u8; 32],
    iv: [u8; 16],
    encrypted_buffer: Vec<u8>,
}

impl<R: Read> RarAesReader<R> {
    pub fn new(reader: R, file: FileBlock, pwd: &str) -> RarAesReader<R> {
        let mut active = false;
        let mut key = [0u8; 32];
        let mut iv = [0u8; 16];

        if let Some(f) = file.extra.file_encryption {
            key = generate_key(&f, pwd);
            iv.copy_from_slice(&f.init);
            active = true;
        }

        RarAesReader {
            reader,
            active,
            buffer: Vec::new(),
            buffer_pos: 0,
            key,
            iv,
            encrypted_buffer: Vec::new(),
        }
    }
}

impl<R: Read> Read for RarAesReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if !self.active {
            return self.reader.read(buf);
        }

        if self.buffer_pos < self.buffer.len() {
            let available = self.buffer.len() - self.buffer_pos;
            let to_copy = buf.len().min(available);
            buf[..to_copy]
                .copy_from_slice(&self.buffer[self.buffer_pos..self.buffer_pos + to_copy]);
            self.buffer_pos += to_copy;
            return Ok(to_copy);
        }

        self.buffer.clear();
        self.buffer_pos = 0;

        let mut temp_buf = vec![0u8; 4096];
        let bytes_read = self.reader.read(&mut temp_buf)?;

        if bytes_read == 0 {
            return Ok(0);
        }

        self.encrypted_buffer
            .extend_from_slice(&temp_buf[..bytes_read]);

        let complete_blocks = self.encrypted_buffer.len() / 16;
        if complete_blocks > 0 {
            let blocks_to_decrypt = complete_blocks * 16;

            // Save last ciphertext block as next IV for CBC chaining
            let mut next_iv = [0u8; 16];
            next_iv
                .copy_from_slice(&self.encrypted_buffer[blocks_to_decrypt - 16..blocks_to_decrypt]);

            let mut data = self.encrypted_buffer[..blocks_to_decrypt].to_vec();
            let dec = Aes256CbcDec::new(&self.key.into(), &self.iv.into());
            if let Ok(pt) = dec.decrypt_padded::<NoPadding>(&mut data) {
                self.buffer.extend_from_slice(pt);
            }

            self.iv = next_iv;
            self.encrypted_buffer.drain(..blocks_to_decrypt);
        }

        if !self.buffer.is_empty() {
            let to_copy = buf.len().min(self.buffer.len());
            buf[..to_copy].copy_from_slice(&self.buffer[..to_copy]);
            self.buffer_pos = to_copy;
            Ok(to_copy)
        } else {
            self.read(buf)
        }
    }
}

impl<R: Read + Seek> Seek for RarAesReader<R> {
    fn seek(&mut self, pos: SeekFrom) -> Result<u64> {
        self.buffer.clear();
        self.buffer_pos = 0;
        self.encrypted_buffer.clear();
        self.reader.seek(pos)
    }
}

/// Generate the decryption key from the encryption block infos
fn generate_key(feb: &FileEncryptionBlock, pwd: &str) -> [u8; 32] {
    let iter_number = 2u32.pow(feb.kdf_count.into());
    let mut key = [0u8; 32];
    let _ = pbkdf2::<Hmac<Sha256>>(pwd.as_bytes(), &feb.salt, iter_number, &mut key);
    key
}

#[test]
fn test_aes_stream_disabled() {
    use std::io::Cursor;

    let data = b"Hello World!";
    let cursor = Cursor::new(data);
    let file = FileBlock::default();

    let mut reader = RarAesReader::new(cursor, file, "");
    let mut buf = [0u8; 12];
    let read_bytes = reader.read(&mut buf).unwrap();

    assert_eq!(read_bytes, 12);
    assert_eq!(&buf, data);
}
