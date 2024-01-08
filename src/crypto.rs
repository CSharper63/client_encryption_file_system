use argon2::{
    password_hash::{rand_core::RngCore, SaltString},
    Argon2,
};
use chacha20poly1305::{
    aead::{generic_array::GenericArray, Aead, OsRng},
    AeadCore, ChaCha20Poly1305, KeyInit,
};

use crate::model::EncryptedAsset;

// TODO verify that OSRng is a valid Crypto RNG

pub type SymmKey = [u8; 32];

/// Use to encrypt data using chacha20poly1305.
pub fn encrypt(key: Vec<u8>, data: Vec<u8>) -> EncryptedAsset {
    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&key));
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng); // 96-bits; unique per message
    let ciphertext = cipher.encrypt(&nonce, data.as_slice()).unwrap();

    let key = EncryptedAsset {
        asset: Some(ciphertext),
        nonce: Some(nonce.to_vec()),
    };
    key
}

/// Use to decrypt data using chacha20poly1305.
pub fn decrypt(key: Vec<u8>, nonce: Vec<u8>, data: Vec<u8>) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&key));

    let plaintext = cipher
        .decrypt(GenericArray::from_slice(&nonce), data.as_slice())
        .unwrap();
    plaintext
}

/// Use to generate symmetric key, this key will be used to encrypt the vault user master key.
pub fn hash_password(plain_password: &str) -> (Vec<u8>, String) {
    let salt = SaltString::generate(&mut OsRng);
    let mut hashed_password = [0u8; 32]; // Can be any desired size
    Argon2::default() // TODO change Argon2id params
        .hash_password_into(
            plain_password.as_bytes(),
            salt.as_str().as_bytes(),
            &mut hashed_password,
        )
        .unwrap();

    (hashed_password.to_vec(), salt.to_string())
}

/// Use to generate the master key, this key will be used to encrypt all the entity keys such as file/dir keys.
pub fn generate_master_key() -> Vec<u8> {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    key.to_vec()
}

/// Use to derive keys from input, in this case the input will be a password hash and the derivation will produce an auth key and a symmetric key.
pub fn kdf(key_material: Vec<u8>) -> (Vec<u8>, Vec<u8>) {
    let mut auth_key = [0u8; 32];
    let mut symmetric_key = [0u8; 32];

    // compute auth key
    Argon2::default()
        .hash_password_into(&key_material, b"0", &mut auth_key)
        .unwrap();
    // compute symmetric key
    Argon2::default()
        .hash_password_into(&key_material, b"1", &mut symmetric_key)
        .unwrap();

    (auth_key.to_vec(), symmetric_key.to_vec())
}
