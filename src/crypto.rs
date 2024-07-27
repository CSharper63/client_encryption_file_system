use std::error::Error;

use argon2::{
    password_hash::{rand_core::RngCore, SaltString},
    Algorithm, Argon2, Params, Version,
};

use hkdf::Hkdf;
use sha2::Sha256;

use chacha20poly1305::{
    aead::{generic_array::GenericArray, Aead, AeadCore, KeyInit, OsRng},
    XChaCha20Poly1305, XNonce,
};
use rsa::{
    pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey},
    sha2, Oaep, RsaPrivateKey, RsaPublicKey,
};

const SYMMETRIC_KEY_SIZE: usize = 32; //in bytes,32 * 8 = 256 bits key
const RSA_KEY_SIZE: usize = 4096; // in bit

use crate::model::DataAsset;

/// Use to encrypt data using extended chacha20poly1305.
pub fn encrypt(
    key: Vec<u8>,
    data: Option<Vec<u8>>,
    nonce: Option<Vec<u8>>,
) -> Result<DataAsset, Box<dyn Error>> {
    if key.len() != SYMMETRIC_KEY_SIZE {
        return Err(format!(
            "Invalid key size. It must be {}. Current is {}",
            SYMMETRIC_KEY_SIZE,
            key.len()
        )
        .into());
    }

    // check if data is present
    let Some(data) = data else {
        return Err("No plaintext provided".into());
    };

    if data.is_empty() {
        return Err("Data is empty".into());
    }

    let stream = XChaCha20Poly1305::new(GenericArray::from_slice(&key));

    // in case of we want to re-encrypt an existing file
    let nonce_2_use = nonce.unwrap_or(XChaCha20Poly1305::generate_nonce(&mut OsRng).to_vec());

    let Ok(ciphertext) = stream.encrypt(XNonce::from_slice(&nonce_2_use), data.as_slice()) else {
        return Err("Unable to encrypt plaintext".into());
    };

    let encrypted = DataAsset::encrypted(Some(ciphertext), Some(nonce_2_use));

    Ok(encrypted)
}

/// Use to decrypt data using xchacha20poly1305.
pub fn decrypt(
    key: Vec<u8>,
    nonce: Option<Vec<u8>>,
    data: Option<Vec<u8>>,
) -> Result<Vec<u8>, Box<dyn Error>> {
    // check if nonce is present
    let Some(nonce) = nonce else {
        return Err("No nonce provided".into());
    };

    // check if data is present
    let Some(data) = data else {
        return Err("No ciphertext provided".into());
    };

    if data.is_empty() {
        return Err("Data is empty".into());
    }

    // decrypt
    let stream = XChaCha20Poly1305::new(GenericArray::from_slice(&key));

    let Ok(plaintext) = stream.decrypt(XNonce::from_slice(&nonce), data.as_slice()) else {
        return Err("Unable to decrypt ciphertext".into());
    };

    return Ok(plaintext);
}

/// Use to generate symmetric key, this key will be used to encrypt the vault user master key.
pub fn hash_password(
    plain_password: &str,
    salt: Option<Vec<u8>>,
) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
    if plain_password.is_empty() {
        return Err("Password is empty".into());
    }

    let salt = salt.unwrap_or(
        SaltString::generate(&mut OsRng)
            .to_string()
            .as_bytes()
            .to_vec(),
    );

    let Ok(params) = Params::new(1048576, 3, 1, Some(SYMMETRIC_KEY_SIZE)) else {
        return Err("Unable to init argon2id params".into());
    };

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut hashed_password = [0u8; SYMMETRIC_KEY_SIZE]; // Can be any desired size

    let _ = argon2.hash_password_into(
        plain_password.as_bytes(),
        salt.as_slice(),
        &mut hashed_password,
    );

    Ok((hashed_password.to_vec(), salt.to_vec()))
}

/// Use to generate the master key, this key will be used to encrypt all the entity keys such as file/dir keys.
pub fn generate_master_key() -> Result<Vec<u8>, Box<dyn Error>> {
    let mut key = [0u8; SYMMETRIC_KEY_SIZE];
    OsRng.fill_bytes(&mut key);
    Ok(key.to_vec())
}

/// Use to derive keys from input, in this case the input will be a password hash and the derivation will produce an auth key and a symmetric key.
pub fn kdf(key_material: Vec<u8>) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
    let mut auth_key = [0u8; SYMMETRIC_KEY_SIZE];
    let mut symmetric_key = [0u8; SYMMETRIC_KEY_SIZE];

    let Ok(kdf) = Hkdf::<Sha256>::from_prk(&key_material.as_slice()) else {
        return Err("Unable to generate kdf from key".into());
    };

    kdf.expand(b"auth_key", &mut auth_key)
        .expect("32 is a valid length for Sha256 to output");

    kdf.expand(b"symm_key", &mut symmetric_key)
        .expect("32 is a valid length for Sha256 to output");

    Ok((auth_key.to_vec(), symmetric_key.to_vec()))
}

/// Use to generate asymmetric public/private keys-pair using RSA-OAEP 4096
pub fn generate_asymm_keys() -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
    let mut rng = OsRng;

    let Ok(priv_key) = RsaPrivateKey::new(&mut rng, RSA_KEY_SIZE) else {
        return Err("Unable to generate RSA private key".into());
    };

    let pub_key = RsaPublicKey::from(&priv_key);

    let Ok(secret) = priv_key.to_pkcs8_der() else {
        return Err("Unable to export RSA private key in DER".into());
    };

    let Ok(public) = pub_key.to_public_key_der() else {
        return Err("Unable to export RSA public key in DER".into());
    };

    Ok((secret.to_bytes().to_vec(), public.to_vec()))
}

/// Use RSA-OAEP to encrypt the data using the public key
pub fn encrypt_asymm(public_key: Vec<u8>, data: Vec<u8>) -> Result<Vec<u8>, Box<dyn Error>> {
    if public_key.is_empty() {
        return Err("Public key is empty".into());
    }

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
    if private_key_bytes.is_empty() {
        return Err("Private key is empty".into());
    }

    if encrypted_data.is_empty() {
        return Err("Data is empty".into());
    }

    let padding = Oaep::new::<Sha256>();

    let priv_key = RsaPrivateKey::from_pkcs8_der(&private_key_bytes)?;

    let decrypted_data: Vec<u8> = priv_key.decrypt(padding, &encrypted_data)?;

    Ok(decrypted_data)
}
