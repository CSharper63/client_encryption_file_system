use std::collections::HashMap;

use rsa::{pkcs8, rand_core::OsRng, RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, NoneAsEmptyString};

use crate::crypto::{self};

fn add_to_path(name: &str) -> String {
    format!("/{}", name)
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FsTree {
    dirs: Option<Vec<DirEntity>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum DataStatus {
    // allow to know if the current processed data are encrypted or not
    Encrypted,
    Decrypted,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DataAsset {
    // can contain encrypted/decrypted data
    #[serde(with = "base58")]
    pub asset: Option<Vec<u8>>,
    #[serde(with = "base58")]
    pub nonce: Option<Vec<u8>>,
    #[serde(skip_serializing)]
    pub status: Option<DataStatus>,
}

#[serde_as]
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct User {
    #[serde_as(as = "NoneAsEmptyString")]
    pub uid: Option<String>,
    pub username: String,
    #[serde(skip_serializing)] // never send the symm key to the server
    pub symmetric_key: Vec<u8>,
    #[serde(with = "base58")]
    pub clear_salt: Option<Vec<u8>>,
    pub master_key: DataAsset,
    #[serde(with = "base58")]
    pub auth_key: Option<Vec<u8>>,
    #[serde(with = "base58")]
    pub public_key: Option<Vec<u8>>,
    pub private_key: DataAsset,
    pub shared_to_others: Option<HashMap<String, String>>,
    pub shared_to_me: Option<HashMap<String, String>>,
}

impl User {
    pub fn generate(username: &str, password: &str) -> Self {
        // generate the hash from password, give the hash and the salt
        let (hash, salt) = crypto::hash_password(password, None);

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
            uid: None,
            username: username.to_string(),
            symmetric_key: symm_key,
            clear_salt: Some(salt),
            master_key: DataAsset {
                asset: Some(master_key),
                nonce: None,
                status: Some(DataStatus::Decrypted),
            },
            auth_key: Some(auth_key),
            public_key: Some(public_key_bytes),
            private_key: DataAsset {
                asset: Some(private_key_bytes),
                nonce: None,
                status: Some(DataStatus::Decrypted),
            },
            shared_to_me: Some(HashMap::new()),
            shared_to_others: Some(HashMap::new()),
        }
    }

    pub fn encrypt(self) -> User {
        let symmetric_key = self.symmetric_key.clone();

        // encrypt the master and asymm private keys using symmetric key
        let encrypted_master_key = crypto::encrypt(
            symmetric_key.clone(),
            self.master_key.asset,
            self.master_key.nonce,
        );
        let encrypted_private_key = crypto::encrypt(
            symmetric_key.clone(),
            self.private_key.asset,
            self.private_key.nonce,
        );

        // this use is encrypted
        User {
            uid: self.uid,
            symmetric_key,
            username: self.username,
            clear_salt: self.clear_salt,
            master_key: DataAsset {
                asset: encrypted_master_key.asset,
                nonce: encrypted_master_key.nonce,
                status: Some(DataStatus::Encrypted),
            },
            auth_key: self.auth_key,
            public_key: self.public_key,
            private_key: DataAsset {
                asset: encrypted_private_key.asset,
                nonce: encrypted_private_key.nonce,
                status: Some(DataStatus::Encrypted),
            },
            shared_to_me: Some(HashMap::new()),
            shared_to_others: Some(HashMap::new()),
        }
    }

    pub fn decrypt(self, password: &str) -> User {
        // use the fetched salt to generate password hash
        let (password_hash, _) =
            crypto::hash_password(password, Some(self.clear_salt.clone().unwrap()));

        // retrieve user symm key using kdf from the password hash
        let (_, user_symm_key) = crypto::kdf(password_hash.try_into().unwrap_or_default());

        // decrypt the master key using user symm key
        let user_master_key = crypto::decrypt(
            user_symm_key.clone(),
            self.master_key.nonce,
            self.master_key.asset,
        )
        .unwrap();

        // decrypt the private asymm key using user symm key
        let user_private_key = crypto::decrypt(
            user_symm_key.clone(),
            self.private_key.nonce,
            self.private_key.asset,
        )
        .unwrap();

        User {
            uid: self.uid,
            username: self.username,
            symmetric_key: user_symm_key.clone(), // decrypted
            clear_salt: self.clear_salt,
            auth_key: self.auth_key, // decrypted
            master_key: DataAsset {
                asset: Some(user_master_key), // decrypted
                nonce: None, // we don't need it anymore as soon as we fetch and decrypted the content from the api
                status: Some(DataStatus::Decrypted),
            },
            public_key: self.public_key,
            private_key: DataAsset {
                asset: Some(user_private_key), // decrypted
                nonce: None,
                status: Some(DataStatus::Decrypted),
            },
            shared_to_me: Some(HashMap::new()),
            shared_to_others: Some(HashMap::new()),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct DirEntity {
    // must be sent to the client while logged in
    pub path: String,
    pub name: DataAsset,
    pub key: DataAsset,
    pub files: Option<Vec<FileEntity>>,
    pub dirs: Option<Vec<DirEntity>>,
}

impl DirEntity {
    // the path is formed with base58 encoded encrypted name

    //TODO create()
    // path refers of the server tree

    // Before all must provide the current
    pub fn create(name: &str, path: &str) -> DirEntity {
        let dir_key = crypto::generate_master_key();
        DirEntity {
            path: path.to_string() + &add_to_path(name),
            name: DataAsset {
                asset: Some(name.as_bytes().to_vec()),
                nonce: None,
                status: Some(DataStatus::Decrypted),
            },
            key: DataAsset {
                asset: Some(dir_key),
                nonce: None,
                status: Some(DataStatus::Decrypted),
            },
            files: None,
            dirs: None,
        }
    }

    // symm key used is the parent dir key
    pub fn encrypt(self, symm_key: Vec<u8>) -> DirEntity {
        // if the dir has already been encrypted a time, use the nonce to reencrypt
        let encrypted_name = crypto::encrypt(symm_key.clone(), self.name.asset, self.name.nonce);
        let encrypted_dir_key = crypto::encrypt(symm_key, self.key.asset, self.key.nonce);

        DirEntity {
            path: self.path,
            name: encrypted_name,
            key: encrypted_dir_key,
            files: self.files,
            dirs: self.dirs,
        }
    }

    pub fn decrypt(self, symm_key: Vec<u8>) -> DirEntity {
        let decrypted_name =
            crypto::decrypt(symm_key.clone(), self.name.nonce.clone(), self.name.asset).unwrap();

        let decrypted_dir_key =
            crypto::decrypt(symm_key.clone(), self.key.nonce.clone(), self.key.asset).unwrap();

        let decrypted_files = self.files.as_ref().map(|files| {
            files
                .iter()
                .map(|file| file.clone().decrypt(symm_key.clone()))
                .collect()
        });

        let decrypted_dirs = self.dirs.as_ref().map(|dirs| {
            dirs.iter()
                .map(|dir| dir.clone().decrypt(symm_key.clone()))
                .collect()
        });

        DirEntity {
            path: self.path,
            name: DataAsset {
                asset: Some(decrypted_name),
                nonce: self.name.nonce.clone(),
                status: Some(DataStatus::Decrypted),
            },
            key: DataAsset {
                asset: Some(decrypted_dir_key),
                nonce: self.key.nonce.clone(),
                status: Some(DataStatus::Decrypted),
            },
            files: decrypted_files,
            dirs: decrypted_dirs,
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct FileEntity {
    pub path: String,
    pub name: DataAsset,
    pub key: DataAsset,
    pub content: DataAsset,
}

impl FileEntity {
    pub fn create(name: &str, content: Vec<u8>, path: &str) -> FileEntity {
        let file_key = crypto::generate_master_key();
        FileEntity {
            path: path.to_string() + &add_to_path(name), // parent path
            name: DataAsset {
                asset: Some(name.as_bytes().to_vec()),
                nonce: None,
                status: Some(DataStatus::Decrypted),
            },
            key: DataAsset {
                asset: Some(file_key),
                nonce: None,
                status: Some(DataStatus::Decrypted),
            },
            content: DataAsset {
                asset: Some(content),
                nonce: None,
                status: Some(DataStatus::Decrypted),
            },
        }
    }

    pub fn encrypt(self, symm_key: Vec<u8>) -> FileEntity {
        // Todo handle while
        let encrypted_name = crypto::encrypt(symm_key.clone(), self.name.asset, self.name.nonce);
        let encrypted_content =
            crypto::encrypt(symm_key.clone(), self.content.asset, self.content.nonce);
        let encrypted_file_key = crypto::encrypt(symm_key, self.key.asset, self.key.nonce);

        FileEntity {
            path: self.path,
            name: encrypted_name,
            key: encrypted_file_key,
            content: encrypted_content,
        }
    }
    pub fn decrypt(self, symm_key: Vec<u8>) -> FileEntity {
        let decrypted_name =
            crypto::decrypt(symm_key.clone(), self.name.nonce.clone(), self.name.asset).unwrap();
        let decrypted_key =
            crypto::decrypt(symm_key.clone(), self.key.nonce.clone(), self.key.asset).unwrap();
        let decrypted_content = crypto::decrypt(
            symm_key.clone(),
            self.content.nonce.clone(),
            self.content.asset,
        )
        .unwrap();

        FileEntity {
            path: self.path.clone(),
            name: DataAsset {
                asset: Some(decrypted_name),
                nonce: self.name.nonce.clone(),
                status: Some(DataStatus::Decrypted),
            },
            key: DataAsset {
                asset: Some(decrypted_key),
                nonce: self.key.nonce.clone(),
                status: Some(DataStatus::Decrypted),
            },
            content: DataAsset {
                asset: Some(decrypted_content),
                nonce: self.content.nonce.clone(),
                status: Some(DataStatus::Decrypted),
            },
        }
    }
}

mod base58 {

    use serde::{Deserialize, Serialize};
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        let base58 = match v {
            Some(v) => Some(bs58::encode(v).into_string()),
            None => None,
        };
        <Option<String>>::serialize(&base58, s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
        let base58 = <Option<String>>::deserialize(d)?;
        match base58 {
            Some(v) => bs58::decode(v.as_bytes())
                .into_vec()
                .map(|v| Some(v))
                .map_err(|e| serde::de::Error::custom(e)),
            None => Ok(None),
        }
    }
}
