use rsa::{pkcs8, rand_core::OsRng, RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};

use crate::crypto::{self, SymmKey};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EncryptedAsset {
    #[serde(with = "base64")]
    pub asset: Option<Vec<u8>>,
    #[serde(with = "base64")]
    pub nonce: Option<Vec<u8>>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct User {
    pub uid: Option<String>,
    pub username: String,
    #[serde(with = "base64")]
    pub symmetric_key: Option<Vec<u8>>,
    pub clear_salt: String,
    pub master_key: EncryptedAsset,
    #[serde(with = "base64")]
    pub auth_key: Option<Vec<u8>>,
    #[serde(with = "base64")]
    pub public_key: Option<Vec<u8>>,

    pub private_key: EncryptedAsset,
}

impl User {
    pub fn generate(username: &str, password: &str) -> Self {
        // generate the hash from password, give the hash and the salt
        let (hash, salt) = crypto::hash_password(password);

        // generate the master key
        let master_key = crypto::generate_master_key();

        // user kdf to derive auth and symm key
        let (auth_key, symm_key) = crypto::kdf(hash.try_into().unwrap());

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
            uid: None,
            username: username.to_string(),
            symmetric_key: Some(symm_key),
            clear_salt: salt,
            master_key: EncryptedAsset {
                asset: Some(master_key),
                nonce: None,
            },
            auth_key: Some(auth_key),
            public_key: Some(public_key_bytes),
            private_key: EncryptedAsset {
                asset: Some(private_key_bytes),
                nonce: None,
            },
        }
    }

    pub fn encrypt(self) -> User {
        let symmetric_key = self.symmetric_key.clone().unwrap();

        // encrypt the master and asymm private keys using symmetric key
        let encrypted_master_key =
            crypto::encrypt(symmetric_key.clone(), self.master_key.asset.unwrap());
        let encrypted_private_key =
            crypto::encrypt(symmetric_key.clone(), self.private_key.asset.unwrap());

        // this use is encrypted
        User {
            uid: self.uid,
            symmetric_key: None,
            username: self.username,
            clear_salt: self.clear_salt,
            master_key: EncryptedAsset {
                asset: encrypted_master_key.asset,
                nonce: encrypted_master_key.nonce,
            },
            auth_key: self.auth_key,
            public_key: self.public_key,
            private_key: EncryptedAsset {
                asset: encrypted_private_key.asset,
                nonce: encrypted_private_key.nonce,
            },
        }
    }
}

mod base64 {
    use base64::engine::general_purpose;
    use base64::Engine as _;
    use serde::{Deserialize, Serialize};
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        let base64 = match v {
            Some(v) => Some(general_purpose::STANDARD.encode(v)),
            None => None,
        };
        <Option<String>>::serialize(&base64, s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
        let base64 = <Option<String>>::deserialize(d)?;
        match base64 {
            Some(v) => general_purpose::STANDARD
                .decode(v.as_bytes())
                .map(|v| Some(v))
                .map_err(|e| serde::de::Error::custom(e)),
            None => Ok(None),
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
