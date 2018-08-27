use crypto::pbkdf2::pbkdf2;
use crypto::hmac::Hmac;
use crypto::sha2::Sha256;
use crypto::buffer::{ ReadBuffer, WriteBuffer, BufferResult };
use crypto::{buffer, aes, blockmodes };
use crypto::aessafe;
use crypto::blockmodes::{CbcDecryptor, PaddingProcessor};
use crypto::symmetriccipher::Decryptor;
use crypto::aes::KeySize;
use failure::Error;
use file;

pub fn decrypt(file: file::File, data: &[u8]) -> Result<Vec<u8>, Error> {
    let fe = file.extra.file_encryption.ok_or(format_err!("Can't access encryption info"))?;
    let iter_number = 2u32.pow(fe.kdf_count.into());

    let mut key = [0u8; 32];

    let mut mac = Hmac::new(Sha256::new(), "test".as_bytes());
    pbkdf2(&mut mac, &fe.salt, iter_number, &mut key);

    // create decryptor and set keys & values
    let mut decryptor = aes_cbc_decryptor(aes::KeySize::KeySize256, &key, &fe.init, blockmodes::NoPadding);

    // create the buffer objects
    let mut buffer = [0; 4096];
    let mut read_buffer = buffer::RefReadBuffer::new(data);
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);
    let mut result = Vec::new();

    loop {
        let r = match decryptor.decrypt(&mut read_buffer, &mut write_buffer, true) {
            Ok(r) => r,
            Err(_) => return Err(format_err!("Can't decrypt")),
        };
        result.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));
        match r {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => { }
        }
    };

    // shorten to defined file length
    result.truncate(file.unpacked_size as usize);

    Ok(result)
}


fn aes_cbc_decryptor<X: PaddingProcessor + Send + 'static>(
        key_size: KeySize,
        key: &[u8],
        iv: &[u8],
        padding: X) -> Box<Decryptor + 'static> {
    match key_size {
        KeySize::KeySize128 => {
            let aes_dec = aessafe::AesSafe128Decryptor::new(key);
            let dec = Box::new(CbcDecryptor::new(aes_dec, padding, iv.to_vec()));
            dec as Box<Decryptor + 'static>
        }
        KeySize::KeySize192 => {
            let aes_dec = aessafe::AesSafe192Decryptor::new(key);
            let dec = Box::new(CbcDecryptor::new(aes_dec, padding, iv.to_vec()));
            dec as Box<Decryptor + 'static>
        }
        KeySize::KeySize256 => {
            let aes_dec = aessafe::AesSafe256Decryptor::new(key);
            let dec = Box::new(CbcDecryptor::new(aes_dec, padding, iv.to_vec()));
            dec as Box<Decryptor + 'static>
        }
    }
}