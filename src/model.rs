use serde::{Deserialize, Serialize};
use serde_with::{serde_as, skip_serializing_none, NoneAsEmptyString};
use std::collections::HashMap;

use crate::crypto::{self};

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct RootTree {
    #[serde(default)]
    pub dirs: Option<Vec<FsEntity>>, // all sub folders
    // toto -> FsEntity -> ref sur toto &FsEntity
    // |
    //  ---- Tete
    // titi
    // tata
    #[serde(default)]
    pub files: Option<Vec<FsEntity>>, // all root files
}

impl RootTree {
    pub fn to_string(&self) -> String {
        serde_json::to_string_pretty(&self).unwrap_or(String::from("Unable to show the tree"))
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone, Copy)]
pub enum DataStatus {
    // allow to know if the current processed data are encrypted or not
    Encrypted,
    Decrypted,
}

#[derive(Default, PartialEq, Eq, Debug, Serialize, Deserialize, Clone)]
pub struct DataAsset {
    // can contain encrypted/decrypted data
    #[serde(with = "base58")]
    pub asset: Option<Vec<u8>>,
    #[serde(with = "base58")]
    pub nonce: Option<Vec<u8>>,
    #[serde(skip_serializing)]
    pub status: Option<DataStatus>,
}

/* #[derive(Default, PartialEq, Eq, Debug, Deserialize, Serialize, Clone)]
pub struct FileEntity {
    pub path: String,
    pub name: DataAsset,
    pub key: DataAsset,
    pub content: DataAsset,
}
 */
#[serde_as]
#[derive(Default, PartialEq, Eq, Debug, Deserialize, Serialize, Clone)]
pub struct FsEntity {
    #[serde_as(as = "NoneAsEmptyString")]
    pub uid: Option<String>,
    #[serde_as(as = "NoneAsEmptyString")]
    pub parent_id: Option<String>,
    pub path: String, // parent path where the dir is stored
    pub name: DataAsset,
    pub key: DataAsset,
    pub entity_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<DataAsset>,
}

#[serde_as]
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct User {
    #[serde_as(as = "NoneAsEmptyString")]
    pub uid: Option<String>,
    pub username: String,
    #[serde(skip_serializing, default)] // !! never send the symm key to the server
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

        // TODO handle if already created
        // asymm crypto -> generate public and private keys
        let (private_key, public_key) = crypto::generate_asymm_keys();

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
            public_key: Some(public_key),
            private_key: DataAsset {
                asset: Some(private_key),
                nonce: None,
                status: Some(DataStatus::Decrypted),
            },
            shared_to_me: Some(HashMap::new()),
            shared_to_others: Some(HashMap::new()),
        }
    }

    /// Use to rebuild symmetric and auth key from the password and the salt obtained by the api
    pub fn rebuild_secret(password: &str, salt: Option<Vec<u8>>) -> (Vec<u8>, Vec<u8>) {
        // generate the hash from password, give the hash and the salt
        let (hash, _) = crypto::hash_password(password, salt);

        // user kdf to derive auth and symm key
        let (auth_key, symm_key) = crypto::kdf(hash);

        (auth_key, symm_key)
    }

    pub fn encrypt(self) -> User {
        println!("Before encryption: {}", self.to_string());

        let symmetric_key = self.symmetric_key.clone();
        let mk = self.master_key.asset.clone();

        // encrypt the master and asymm private keys using symmetric key
        let encrypted_master_key =
            crypto::encrypt(symmetric_key.clone(), mk.clone(), self.master_key.nonce);
        println!("Master key has been encrypted");

        // TODO must be encrypted with the master key and NOT THE SYMMETRIC KEY, EXPECTED TO CHANGE IN THE FUTURE
        let encrypted_private_key =
            crypto::encrypt(mk.unwrap(), self.private_key.asset, self.private_key.nonce);
        println!("Private key has been encrypted");

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

    pub fn decrypt(self, password: &str, salt: Option<Vec<u8>>) -> User {
        // use the fetched salt to generate password hash
        let (password_hash, _) = crypto::hash_password(password, salt.clone());

        // retrieve user symm key using kdf from the password hash
        let (_, user_symm_key) = crypto::kdf(password_hash.try_into().unwrap_or_default());

        // decrypt the master key using user symm key
        let user_master_key = crypto::decrypt(
            user_symm_key.clone(),
            self.master_key.nonce.clone(),
            self.master_key.asset,
        )
        .unwrap();

        // decrypt the private asymm key using user symm key
        let user_private_key = crypto::decrypt(
            user_master_key.clone(),
            self.private_key.nonce.clone(),
            self.private_key.asset,
        )
        .unwrap();

        User {
            uid: self.uid,
            username: self.username,
            symmetric_key: user_symm_key.clone(), // decrypted
            clear_salt: salt,
            auth_key: self.auth_key, // decrypted
            master_key: DataAsset {
                asset: Some(user_master_key), // decrypted
                nonce: self.master_key.nonce, // we don't need it anymore as soon as we fetch and decrypted the content from the api
                status: Some(DataStatus::Decrypted),
            },
            public_key: self.public_key,
            private_key: DataAsset {
                asset: Some(user_private_key), // decrypted
                nonce: self.private_key.nonce.clone(),
                status: Some(DataStatus::Decrypted),
            },
            shared_to_me: Some(HashMap::new()),
            shared_to_others: Some(HashMap::new()),
        }
    }

    pub fn to_string(&self) -> String {
        // !!! The output contains secret key materials
        serde_json::to_string_pretty(&self).unwrap_or(String::from("Unable to display the user"))
    }
}

impl FsEntity {
    // Ajoute un FsEntity au vector sub_dirs
    /*  pub fn add_sub_dir(&mut self, sub_dir: FsEntity) {
           if let Some(sub_dirs) = &mut self.sub_dirs {
               sub_dirs.push(sub_dir);
           } else {
               self.sub_dirs = Some(vec![sub_dir]);
           }
       }
    */
    // Before all must provide the current
    pub fn create(name: &str, path: &str, content: Option<Vec<u8>>, parent_id: &str) -> FsEntity {
        let dir_key = crypto::generate_master_key();
        let mut content_2_process: Option<DataAsset> = None;

        let entity_type = if content.is_none() {
            // if it s a dir
            String::from("dir")
        } else {
            // else we create the content
            content_2_process = Some(DataAsset {
                asset: content,
                nonce: None,
                status: Some(DataStatus::Decrypted),
            });
            String::from("file")
        };

        FsEntity {
            uid: None,
            content: content_2_process,
            parent_id: Some(parent_id.to_string()),
            entity_type: entity_type,
            path: path.to_string(),
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
            /*    files: Some(Vec::default()),
            sub_dirs: Some(Vec::default()), */
        }
    }

    // symm key used is the parent dir key
    pub fn encrypt(self, symm_key: Vec<u8>) -> FsEntity {
        println!("dir before encryption: {}", self.clone().to_string());

        // if the dir has already been encrypted a time, use the nonce to reencrypt
        let encrypted_name = crypto::encrypt(symm_key.clone(), self.name.asset, self.name.nonce);
        println!("Name has been encrypted");
        let encrypted_dir_key = crypto::encrypt(
            symm_key.clone(),
            self.key.clone().asset,
            self.key.clone().nonce,
        );
        println!("Dir key has been encrypted");

        let mut encrypted_content: Option<DataAsset> = None;

        if self.entity_type == "file" {
            // if it is a file it must be encrypted with its own key

            encrypted_content = Some(crypto::encrypt(
                self.key.asset.unwrap(), // for a file the content
                self.content.clone().unwrap().asset,
                self.content.unwrap().nonce,
            ));
        }

        FsEntity {
            uid: self.uid,
            content: encrypted_content,
            parent_id: self.parent_id,
            entity_type: self.entity_type,
            path: self.path, /* + &add_to_path(&base58_name_for_path) */
            // only add the encrypted file name when encrypt the name before send it to the api
            name: encrypted_name,
            key: encrypted_dir_key,
        }
    }

    // happends when fetching tree from api so must be decrypted
    pub fn decrypt(self, symm_key: Vec<u8>) -> FsEntity {
        let name = self.name.asset.unwrap();

        let decrypted_name = crypto::decrypt(
            symm_key.clone(),
            self.name.nonce.clone(),
            Some(name.clone()),
        )
        .unwrap();

        let decrypted_dir_key = crypto::decrypt(
            symm_key.clone(),
            self.key.nonce.clone(),
            self.key.clone().asset,
        )
        .unwrap();

        let decrypted_content = if self.entity_type == "file" {
            Some(DataAsset {
                asset: crypto::decrypt(
                    self.key.clone().asset.unwrap(),
                    self.content.clone().unwrap().nonce.clone(),
                    self.key.asset,
                ),
                nonce: self.content.unwrap().nonce.clone(),
                status: Some(DataStatus::Decrypted),
            })
        } else {
            None
        };

        FsEntity {
            uid: self.uid,
            parent_id: None,
            path: self.path,
            entity_type: self.entity_type,
            content: decrypted_content,
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
            /*   files: decrypted_files,
            sub_dirs: decrypted_dirs, */
        }
    }

    /// Display name as string
    pub fn show_name(&self) -> String {
        String::from_utf8(self.name.clone().asset.unwrap()).unwrap()
    }

    pub fn encrypted_name(&self) -> String {
        bs58::encode(&self.name.asset.clone().unwrap()).into_string()
    }

    pub fn to_string(&self) -> String {
        serde_json::to_string_pretty(&self).unwrap()
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
