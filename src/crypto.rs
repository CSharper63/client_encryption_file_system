use argon2::{
    password_hash::{rand_core::RngCore, SaltString},
    Argon2,
};
use chacha20poly1305::{
    aead::{generic_array::GenericArray, Aead, AeadCore, KeyInit, OsRng},
    XChaCha20Poly1305, XNonce,
};
use rsa::{pkcs8, RsaPrivateKey, RsaPublicKey};

use crate::model::{DataAsset, DataStatus};

// TODO verify that OSRng is a valid Crypto RNG

/// Use to encrypt data using extended chacha20poly1305.
pub fn encrypt(key: Vec<u8>, data: Option<Vec<u8>>, nonce: Option<Vec<u8>>) -> DataAsset {
    match data {
        Some(data) => {
            let cipher = XChaCha20Poly1305::new(GenericArray::from_slice(&key));

            // in case of we want to re-encrypt an existing file
            // TODO verify nonce size
            let nonce_2_use =
                nonce.unwrap_or(XChaCha20Poly1305::generate_nonce(&mut OsRng).to_vec());

            let ciphertext = cipher
                .encrypt(XNonce::from_slice(&nonce_2_use), data.as_slice())
                .unwrap();

            let key = DataAsset {
                asset: Some(ciphertext),
                nonce: Some(nonce_2_use),
                status: Some(DataStatus::Encrypted),
            };
            key
        }
        None => DataAsset {
            asset: None,
            nonce: None,
            status: None,
        },
    }
}

/// Use to decrypt data using chacha20poly1305.
pub fn decrypt(key: Vec<u8>, nonce: Option<Vec<u8>>, data: Option<Vec<u8>>) -> Option<Vec<u8>> {
    let nonce_set: bool;
    // verify if nonce is present
    match nonce {
        Some(_) => nonce_set = true,
        None => nonce_set = false,
    }

    // init decryption only if nonce is set
    if nonce_set {
        match data {
            Some(data) => {
                let cipher = XChaCha20Poly1305::new(GenericArray::from_slice(&key));

                let plaintext = cipher
                    .decrypt(XNonce::from_slice(&nonce.unwrap()), data.as_slice())
                    .unwrap();
                return Some(plaintext);
            }
            None => {
                return None;
            }
        }
    } else {
        return None;
    }
}

/// Use to generate symmetric key, this key will be used to encrypt the vault user master key.
pub fn hash_password(plain_password: &str, salt: Option<Vec<u8>>) -> (Vec<u8>, Vec<u8>) {
    let salt_2_process: Vec<u8>;
    match salt {
        Some(salt_user) => {
            salt_2_process = salt_user;
        }
        None => {
            salt_2_process = SaltString::generate(&mut OsRng)
                .to_string()
                .as_bytes()
                .to_vec();
        }
    };

    let mut hashed_password = [0u8; 32]; // Can be any desired size
    Argon2::default() // TODO change Argon2id params
        .hash_password_into(
            plain_password.as_bytes(),
            salt_2_process.as_slice(),
            &mut hashed_password,
        )
        .unwrap();

    (hashed_password.to_vec(), salt_2_process.to_vec())
}

/// Use to generate the master key, this key will be used to encrypt all the entity keys such as file/dir keys.
pub fn generate_master_key() -> Vec<u8> {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    key.to_vec()
}

/// Use to derive keys from input, in this case the input will be a password hash and the derivation will produce an auth key and a symmetric key.
pub fn kdf(key_material: Vec<u8>) -> (Vec<u8>, Vec<u8>) {
    //TODO concat auto gen salt to the key
    let mut auth_key = [0u8; 32];
    let mut symmetric_key = [0u8; 32];

    // compute auth key
    Argon2::default()
        .hash_password_into(&key_material, b"PI6KXZtYonAI8dc9", &mut auth_key)
        .unwrap();
    // compute symmetric key
    Argon2::default()
        .hash_password_into(&key_material, b"OG08sRT3j1e0wH5m", &mut symmetric_key)
        .unwrap();

    (auth_key.to_vec(), symmetric_key.to_vec())
}

/// Use to generate asymmetric public/private keys-pair using RSA-OAEP 4096
pub fn generate_asymm_keys() -> (Vec<u8>, Vec<u8>) {
    let mut rng = OsRng;
    let bits = 256; // !! for test purposes only
    let priv_key = RsaPrivateKey::new(&mut rng, bits).unwrap();
    let private_key_bytes = pkcs8::EncodePrivateKey::to_pkcs8_der(&priv_key)
        .unwrap()
        .as_bytes()
        .to_vec();
    let pub_key = RsaPublicKey::from(&priv_key);
    let public_key_bytes = pkcs8::EncodePublicKey::to_public_key_der(&pub_key)
        .unwrap()
        .as_bytes()
        .to_vec();

    (private_key_bytes, public_key_bytes)
}
