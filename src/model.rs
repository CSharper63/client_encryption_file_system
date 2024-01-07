use base64::{engine::general_purpose, Engine as _};
use rsa::{pkcs8, rand_core::OsRng, RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};

use crate::crypto::{self, SymmKey};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EncryptedAsset {
    pub asset: Vec<u8>,
    pub nonce: Vec<u8>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct User {
    pub uid: String,
    pub username: String,
    pub symmetric_key: Vec<u8>,
    pub clear_salt: String,
    pub master_key: Vec<u8>,
    pub auth_key: Vec<u8>,
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
}

impl User {
    pub fn generate(username: &str, password: &str) -> Self {
        // generate the hash from password, give the hash and the salt
        let (hash, salt) = crypto::hash_password(password);

        // generate the master key
        let master_key = crypto::generate_master_key();

        // user kdf to derive auth and symm key
        let (auth_key, symm_key) = crypto::kdf(hash);

        // asymm crypto -> generate public and private keys
        let mut rng = OsRng;
        let bits = 4096;
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

        User {
            uid: "".to_string(),
            username: username.to_string(),
            symmetric_key: symm_key.to_vec(),
            clear_salt: salt,
            master_key: master_key.to_vec(),
            auth_key: auth_key.to_vec(),
            public_key: public_key_bytes,
            private_key: private_key_bytes,
        }
    }

    pub fn encrypt_n_convert_to_b64(self) -> EncryptedB64User {
        // encrypt the master and asymm private keys using symmetric key
        let encrypted_master_key = crypto::encrypt(
            self.symmetric_key.clone().try_into().unwrap(),
            self.master_key,
        );
        let encrypted_private_key = crypto::encrypt(
            self.symmetric_key.clone().try_into().unwrap(),
            self.private_key,
        );

        EncryptedB64User {
            uid: self.uid,
            username: self.username,
            clear_salt: self.clear_salt,
            encrypted_master_key: EncryptedAssetB64 {
                asset: general_purpose::STANDARD.encode(encrypted_master_key.asset),
                nonce: general_purpose::STANDARD.encode(encrypted_master_key.nonce),
            },
            auth_key: general_purpose::STANDARD.encode(&self.auth_key),
            public_key: general_purpose::STANDARD.encode(&self.public_key),
            encrypted_private_key: EncryptedAssetB64 {
                asset: general_purpose::STANDARD.encode(encrypted_private_key.asset),
                nonce: general_purpose::STANDARD.encode(encrypted_private_key.nonce),
            },
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct DirEntity {
    // must be sent to the client while logged in
    pub path: String,
    pub encrypted_name: EncryptedAsset,
    pub encrypted_key: EncryptedAsset,
    pub files: Vec<FileEntity>,
    pub dirs: Vec<DirEntity>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct FileEntity {
    pub path: String,
    pub encrypted_name: EncryptedAsset,
    pub encrypted_key: EncryptedAsset,
    pub encrypted_content: EncryptedAsset,
}

// ================= Use to send data encoded in b64 to the API ============================
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EncryptedAssetB64 {
    pub asset: String,
    pub nonce: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct EncryptedB64User {
    pub uid: String,
    pub username: String,
    pub clear_salt: String,
    pub encrypted_master_key: EncryptedAssetB64,
    pub auth_key: String,
    pub public_key: String,
    pub encrypted_private_key: EncryptedAssetB64,
}

// =============== Use to send file/dir to the api
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EncryptedFileB64 {
    pub path: String,
    pub encrypted_name: EncryptedAssetB64,
    pub encrypted_key: EncryptedAssetB64,
    pub encrypted_content: EncryptedAssetB64,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct EncryptedDirB64 {
    pub path: String,
    pub encrypted_name: EncryptedAssetB64,
    pub encrypted_key: EncryptedAssetB64,
    pub files: Vec<EncryptedFileB64>,
    pub dirs: Vec<EncryptedDirB64>,
}
