use std::error::Error;

use argon2::{
    password_hash::{rand_core::RngCore, SaltString},
    Argon2,
};
use blake2::{
    digest::{Update, VariableOutput},
    Blake2bVar,
};

use hkdf::Hkdf;
use sha2::{Digest, Sha256};

use chacha20poly1305::{
    aead::{generic_array::GenericArray, Aead, AeadCore, KeyInit, OsRng},
    XChaCha20Poly1305, XNonce,
};
use rsa::{
    pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey},
    sha2, Oaep, RsaPrivateKey, RsaPublicKey,
};

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
                .map_err(|e| format!("Error while encrypting: {}", e));

            let key = DataAsset {
                asset: Some(ciphertext.unwrap()),
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
                    .map_err(|e| format!("Error while decrypting: {}", e));
                return Some(plaintext.unwrap());
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
    const OUTPUT_SIZE: usize = 32;
    let mut auth_key = [0u8; OUTPUT_SIZE];
    let mut symmetric_key = [0u8; OUTPUT_SIZE];

    let mut hasher = Blake2bVar::new(OUTPUT_SIZE).unwrap();
    println!("Blake ok");
    // salt for auth key
    hasher.update(&key_material);
    let mut auth_salt = [0u8; OUTPUT_SIZE];
    hasher.finalize_variable(&mut auth_salt).unwrap();

    let auth_kdf = Hkdf::<Sha256>::new(Some(&auth_salt), &key_material);

    auth_kdf
        .expand(b"", &mut auth_key)
        .expect("32 is a valid length for Sha256 to output");

    // salt for symm key
    let symm_salt = Sha256::digest(key_material.clone());
    println!("auth_kdf ok");

    let symm_kdf = Hkdf::<Sha256>::new(Some(&symm_salt), &key_material);

    symm_kdf
        .expand(b"", &mut symmetric_key)
        .expect("32 is a valid length for Sha256 to output");

    println!("symm_kdf ok");

    (auth_key.to_vec(), symmetric_key.to_vec())
}

/// Use to generate asymmetric public/private keys-pair using RSA-OAEP 4096
pub fn generate_asymm_keys() -> (Vec<u8>, Vec<u8>) {
    let mut rng = OsRng;
    let bits = 4096; // !! for test purposes only
    let priv_key = RsaPrivateKey::new(&mut rng, bits).unwrap();
    let pub_key = RsaPublicKey::from(&priv_key);
    let secret = priv_key.to_pkcs8_der().unwrap();
    let public = pub_key.to_public_key_der().unwrap();

    (secret.to_bytes().to_vec(), public.to_vec())
}

/// Use RSA-OAEP to encrypt the data using the public key
pub fn encrypt_asymm(public_key: Vec<u8>, data: Vec<u8>) -> Result<Vec<u8>, Box<dyn Error>> {
    let padding = Oaep::new::<Sha256>();

    let public_key =
        RsaPublicKey::from_public_key_der(&public_key).expect("failed to decode public key");

    let mut rng = OsRng;
    let encrypted_data = public_key.encrypt(&mut rng, padding, &data)?;

    Ok(encrypted_data)
}

/// Use RSA-OAEP to decrypt the data using the private key
pub fn decrypt_asymm(
    private_key_bytes: Vec<u8>,
    encrypted_data: Vec<u8>,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let padding = Oaep::new::<Sha256>();

    let priv_key = RsaPrivateKey::from_pkcs8_der(&private_key_bytes)?;

    let decrypted_data: Vec<u8> = priv_key.decrypt(padding, &encrypted_data)?;

    Ok(decrypted_data)
}
