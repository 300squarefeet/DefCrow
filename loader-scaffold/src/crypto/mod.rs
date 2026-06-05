use aes::Aes256;
use cbc::{Encryptor, Decryptor};
use cbc::cipher::{BlockEncryptMut, BlockDecryptMut, KeyIvInit, block_padding::Pkcs7};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, aead::{Aead, KeyInit}};

pub fn encrypt_aes256(plaintext: &[u8], key: &[u8; 32], iv: &[u8; 16]) -> Vec<u8> {
    let enc = Encryptor::<Aes256>::new(key.into(), iv.into());
    enc.encrypt_padded_vec_mut::<Pkcs7>(plaintext)
}

pub fn decrypt_aes256(ciphertext: &[u8], key: &[u8; 32], iv: &[u8; 16]) -> Result<Vec<u8>, &'static str> {
    let dec = Decryptor::<Aes256>::new(key.into(), iv.into());
    dec.decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
        .map_err(|_| "AES-256 decryption failed")
}

pub fn encrypt_chacha20(plaintext: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher.encrypt(Nonce::from_slice(nonce), plaintext).unwrap()
}

pub fn decrypt_chacha20(ciphertext: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> Result<Vec<u8>, &'static str> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher.decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| "ChaCha20 decryption failed")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes256_roundtrip() {
        let key = [0x42u8; 32];
        let iv  = [0x13u8; 16];
        let plaintext = b"hello defcrow shellcode padding!";
        let ciphertext = encrypt_aes256(plaintext, &key, &iv);
        let recovered  = decrypt_aes256(&ciphertext, &key, &iv).unwrap();
        assert_eq!(recovered, plaintext.to_vec());
    }

    #[test]
    fn test_chacha20_roundtrip() {
        let key   = [0x55u8; 32];
        let nonce = [0xAAu8; 12];
        let plaintext = b"shellcode bytes here 1234567890!";
        let ciphertext = encrypt_chacha20(plaintext, &key, &nonce);
        let recovered  = decrypt_chacha20(&ciphertext, &key, &nonce).unwrap();
        assert_eq!(recovered, plaintext.to_vec());
    }

    #[test]
    fn test_aes256_wrong_key_fails() {
        let key = [0x42u8; 32];
        let iv  = [0x13u8; 16];
        let ciphertext = encrypt_aes256(b"hello defcrow shellcode padding!", &key, &iv);
        let wrong_key = [0x99u8; 32];
        let result = decrypt_aes256(&ciphertext, &wrong_key, &iv);
        let failed = result.is_err() || result.unwrap() != b"hello defcrow shellcode padding!";
        assert!(failed, "Wrong key should not decrypt correctly");
    }
}
