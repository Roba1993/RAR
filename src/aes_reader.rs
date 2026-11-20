use aes::Aes256;
use cbc::cipher::{block_padding::NoPadding, BlockModeDecrypt, KeyIvInit};
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use std::io::{Read, Result, Seek, SeekFrom};

use crate::extra_block::FileEncryptionBlock;

type Aes256CbcDec = cbc::Decryptor<Aes256>;
type HmacSha256 = Hmac<Sha256>;

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
    /// Decrypt `reader` with `key` and the initialization vector `iv`,
    /// or pass the data through when `key` is `None`.
    pub fn new(reader: R, key: Option<([u8; 32], [u8; 16])>) -> RarAesReader<R> {
        let (active, (key, iv)) = match key {
            Some(key_iv) => (true, key_iv),
            None => (false, ([0; 32], [0; 16])),
        };

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

/// Keys derived from the password of an encrypted file.
pub struct FileKeys {
    /// AES-256 key of the file data.
    pub key: [u8; 32],
    /// HMAC key used for the checksums when `tweaked_crc` is set.
    hash_key: [u8; 32],
    /// Value to compare with the password check of the encryption record.
    pw_check: [u8; 8],
}

impl FileKeys {
    /// Derive the keys like RAR 5.0: PBKDF2-HMAC-SHA256 gives the AES key after
    /// 2^kdf_count iterations, the hash key after 16 and the password check
    /// after 32 more iterations of the same chain.
    pub fn derive(feb: &FileEncryptionBlock, pwd: &str) -> FileKeys {
        let mac = HmacSha256::new_from_slice(pwd.as_bytes()).expect("HMAC accepts any key size");
        let hmac = |data: &[u8]| -> [u8; 32] {
            let mut m = mac.clone();
            m.update(data);
            m.finalize().into_bytes().into()
        };

        // first block of PBKDF2: salt followed by the block index 1
        let mut salt = feb.salt.to_vec();
        salt.extend_from_slice(&1u32.to_be_bytes());
        let mut u = hmac(&salt);
        let mut acc = u;
        let mut outputs = [[0u8; 32]; 3];
        let iterations = [(1u32 << feb.kdf_count) - 1, 16, 16];
        for (output, count) in outputs.iter_mut().zip(iterations) {
            for _ in 0..count {
                u = hmac(&u);
                acc.iter_mut().zip(&u).for_each(|(a, b)| *a ^= b);
            }
            *output = acc;
        }

        let mut pw_check = [0u8; 8];
        for (i, b) in outputs[2].iter().enumerate() {
            pw_check[i % 8] ^= b;
        }
        FileKeys {
            key: outputs[0],
            hash_key: outputs[1],
            pw_check,
        }
    }

    /// False if the encryption record can tell that the password is wrong.
    pub fn password_matches(&self, feb: &FileEncryptionBlock) -> bool {
        if !feb.flags.pw_check_data {
            return true;
        }
        // The record holds 8 check bytes and the start of their SHA-256 as
        // protection against a damaged record, which then can't be used.
        let (check, sum) = feb.pw_check.split_at(8);
        if Sha256::digest(check)[..4] != *sum {
            return true;
        }
        check == self.pw_check
    }

    /// Convert a CRC32 of the data into the value stored for files with
    /// `tweaked_crc`, which doesn't reveal anything about the data.
    pub fn tweak_crc(&self, crc: u32) -> u32 {
        let mut mac = HmacSha256::new_from_slice(&self.hash_key).expect("32 byte key");
        mac.update(&crc.to_le_bytes());
        mac.finalize()
            .into_bytes()
            .iter()
            .enumerate()
            .fold(0, |acc, (i, &b)| acc ^ (u32::from(b) << ((i % 4) * 8)))
    }
}

#[test]
fn test_aes_stream_disabled() {
    use std::io::Cursor;

    let data = b"Hello World!";
    let cursor = Cursor::new(data);
    let mut reader = RarAesReader::new(cursor, None);
    let mut buf = [0u8; 12];
    let read_bytes = reader.read(&mut buf).unwrap();

    assert_eq!(read_bytes, 12);
    assert_eq!(&buf, data);
}

#[test]
fn test_derive_keys_matches_pbkdf2() {
    // with 2^1 iterations, PBKDF2 gives U1 ^ U2
    let feb = FileEncryptionBlock {
        kdf_count: 1,
        salt: *b"0123456789abcdef",
        ..Default::default()
    };
    let keys = FileKeys::derive(&feb, "password");

    // reference: PBKDF2 = U1 ^ U2
    let mut mac = HmacSha256::new_from_slice(b"password").unwrap();
    mac.update(b"0123456789abcdef\0\0\0\x01");
    let u1: [u8; 32] = mac.finalize().into_bytes().into();
    let mut mac = HmacSha256::new_from_slice(b"password").unwrap();
    mac.update(&u1);
    let u2: [u8; 32] = mac.finalize().into_bytes().into();
    let expected: Vec<u8> = u1.iter().zip(&u2).map(|(a, b)| a ^ b).collect();
    assert_eq!(keys.key.to_vec(), expected);
}
