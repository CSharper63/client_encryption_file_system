use cliclack::spinner;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, NoneAsEmptyString};

use crate::crypto;
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

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Sharing {
    #[serde(with = "base58")]
    pub key: Option<Vec<u8>>,
    pub entity_uid: String, // shared entity
    pub owner_id: String,   // owner that shared the entity
    pub user_id: String,    // User id I share with
}

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

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PublicKeyMaterial {
    #[serde(with = "base58")]
    pub public_key: Option<Vec<u8>>,
    pub owner_id: Option<String>,
}

impl FsEntity {
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
        }
    }

    // symm key used is the parent dir key
    pub fn encrypt(self, parent_key: Vec<u8>) -> FsEntity {
        let mut spin = spinner();
        spin.start(format!("Encrypting {}...", self.entity_type));
        // if the dir has already been encrypted a time, use the nonce to reencrypt
        let encrypted_name = crypto::encrypt(
            self.key.clone().asset.unwrap(),
            self.name.asset,
            self.name.nonce,
        );

        let encrypted_key = crypto::encrypt(
            parent_key.clone(),
            self.key.clone().asset,
            self.key.clone().nonce,
        );

        let mut encrypted_content: Option<DataAsset> = None;

        if self.entity_type == "file" {
            // if it is a file it must be encrypted with its own key
            encrypted_content = Some(crypto::encrypt(
                self.key.asset.unwrap(), // for a file the content
                self.content.clone().unwrap().asset,
                self.content.unwrap().nonce,
            ));
        }

        spin.stop(format!("{} successfully encrypted", self.entity_type));

        FsEntity {
            uid: self.uid,
            content: encrypted_content,
            parent_id: self.parent_id,
            entity_type: self.entity_type,
            path: self.path, /* + &add_to_path(&base58_name_for_path) */
            // only add the encrypted file name when encrypt the name before send it to the api
            name: encrypted_name,
            key: encrypted_key,
        }
    }

    // happends when fetching tree from api so must be decrypted
    pub fn decrypt(self, parent_key: Vec<u8>) -> FsEntity {
        let mut spin = spinner();
        spin.start(format!("Decrypting {}...", self.entity_type));
        // decrypt the entity key to decrypt the rest
        let decrypted_key = crypto::decrypt(
            parent_key.clone(),
            self.key.nonce.clone(),
            self.key.clone().asset,
        )
        .unwrap();

        // decrpyted with own key
        let decrypted_name = crypto::decrypt(
            decrypted_key.clone(),
            self.name.nonce.clone(),
            self.name.clone().asset,
        )
        .unwrap();

        let decrypted_content = if self.entity_type == "file" {
            Some(DataAsset {
                asset: crypto::decrypt(
                    decrypted_key.clone(),
                    self.content.clone().unwrap().nonce.clone(),
                    self.content.clone().unwrap().asset,
                ),
                nonce: self.content.unwrap().nonce.clone(),
                status: Some(DataStatus::Decrypted),
            })
        } else {
            None
        };

        spin.stop(format!("{} successfully decrypted", self.entity_type));

        FsEntity {
            uid: self.uid,
            parent_id: self.parent_id,
            path: self.path,
            entity_type: self.entity_type,
            content: decrypted_content,
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
        }
    }

    pub fn decrypt_from_dir_key(self, dir_key: Vec<u8>) -> FsEntity {
        // decrypt the entity key to decrypt the rest
        let mut spin = spinner();
        spin.start(format!("Decrypting {}...", self.entity_type));
        // decrpyted with own key
        let decrypted_name = crypto::decrypt(
            dir_key.clone(),
            self.name.nonce.clone(),
            self.name.clone().asset,
        )
        .unwrap();

        let decrypted_content = if self.entity_type == "file" {
            Some(DataAsset {
                asset: crypto::decrypt(
                    dir_key.clone(),
                    self.content.clone().unwrap().nonce.clone(),
                    self.content.clone().unwrap().asset,
                ),
                nonce: self.content.unwrap().nonce.clone(),
                status: Some(DataStatus::Decrypted),
            })
        } else {
            None
        };
        spin.stop(format!("{} successfully decrypted", self.entity_type));

        FsEntity {
            uid: self.uid,
            parent_id: self.parent_id,
            path: self.path,
            entity_type: self.entity_type,
            content: decrypted_content,
            name: DataAsset {
                asset: Some(decrypted_name),
                nonce: self.name.nonce.clone(),
                status: Some(DataStatus::Decrypted),
            },
            key: DataAsset {
                asset: Some(dir_key),
                nonce: self.key.nonce.clone(),
                status: Some(DataStatus::Decrypted),
            },
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
    pub shared_to_others: Option<Vec<Sharing>>,
    pub shared_to_me: Option<Vec<Sharing>>,
}

impl User {
    pub fn generate(username: &str, password: &str) -> Self {
        let mut spin = spinner();
        spin.start("Generating your keys");
        // generate the hash from password, give the hash and the salt
        let (hash, salt) = crypto::hash_password(password, None);

        // generate the master key
        let master_key = crypto::generate_master_key();

        // user kdf to derive auth and symm key
        let (auth_key, symm_key) = crypto::kdf(hash);
        // TODO handle if already created
        // asymm crypto -> generate public and private keys
        let (private_key, public_key) = crypto::generate_asymm_keys();

        spin.stop("Keys successfully generated");

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
            shared_to_me: Some(Vec::new()),
            shared_to_others: Some(Vec::new()),
        }
    }

    pub fn find_sharing_by_entity_id(&self, entity_id: &str) -> Option<Sharing> {
        self.shared_to_others
            .as_ref()?
            .iter()
            .find(|sharing| sharing.entity_uid == entity_id)
            .cloned()
    }

    pub fn is_entity_shared(&self, entity_id: &str) -> bool {
        if let Some(shared_to_others) = &self.shared_to_others {
            if shared_to_others
                .iter()
                .any(|sharing| sharing.entity_uid == entity_id)
            {
                return true;
            }
        }

        false
    }

    pub fn revoke_share(&mut self, entity_id: &str) {
        if let Some(shared_to_others) = &mut self.shared_to_others {
            shared_to_others.retain(|sharing| sharing.entity_uid != entity_id);
        }
    }

    pub fn share(&mut self, sharing: &Sharing) {
        if self.shared_to_others.is_none() {
            self.shared_to_others = Some(Vec::new());
        }

        // Ajouter le partage à la liste
        if let Some(shared_to_others) = &mut self.shared_to_others {
            // Vérifier si le partage existe déjà pour éviter les doublons
            if !shared_to_others
                .iter()
                .any(|s| s.entity_uid == sharing.entity_uid)
            {
                shared_to_others.push(sharing.clone());
            }
        }
    }

    /// Use to rebuild symmetric and auth key from the password and the salt obtained by the api
    pub fn rebuild_secret(password: &str, salt: Option<Vec<u8>>) -> (Vec<u8>, Vec<u8>) {
        let mut spin = spinner();
        spin.start("Rebuilding your keys...");
        // generate the hash from password, give the hash and the salt
        let (hash, _) = crypto::hash_password(password, salt);

        // user kdf to derive auth and symm key
        let (auth_key, symm_key) = crypto::kdf(hash);
        spin.stop("Keys successfully rebuilt");

        (auth_key, symm_key)
    }

    pub fn encrypt(self) -> User {
        let mut spin = spinner();
        spin.start("Encrypting your profile...");
        let symmetric_key = self.symmetric_key.clone();
        let mk = self.master_key.asset.clone();

        // encrypt the master and asymm private keys using symmetric key
        let encrypted_master_key =
            crypto::encrypt(symmetric_key.clone(), mk.clone(), self.master_key.nonce);

        let encrypted_private_key =
            crypto::encrypt(mk.unwrap(), self.private_key.asset, self.private_key.nonce);

        spin.stop("Profile successfully encrypted");

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
            shared_to_me: Some(Vec::new()),
            shared_to_others: Some(Vec::new()),
        }
    }

    pub fn decrypt(mut self, password: &str, salt: Option<Vec<u8>>) -> User {
        let mut spin = spinner();
        spin.start("Decrypting your profile...");
        // use the fetched salt to generate password hash
        let (password_hash, auth_key) = crypto::hash_password(password, salt.clone());

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
        spin.stop("Profile successfully decrypted");

        if let Some(shared_to_me) = &mut self.shared_to_me {
            for sharing in shared_to_me.iter_mut() {
                if let Some(encrypted_key) = &sharing.key {
                    // decrypt the entity key
                    let decrypted_key =
                        crypto::decrypt_asymm(user_private_key.clone(), encrypted_key.to_vec())
                            .expect("failed to decrypt sharing key");
                    // update the key
                    sharing.key = Some(decrypted_key);
                }
            }
        }

        User {
            uid: self.uid,
            username: self.username,
            symmetric_key: user_symm_key.clone(), // decrypted
            clear_salt: salt,
            auth_key: Some(auth_key), // decrypted
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
            shared_to_me: self.shared_to_me,
            shared_to_others: self.shared_to_others,
        }
    }

    pub fn update_password(
        &self,
        old_password: &str,
        new_password: &str,
    ) -> (Option<User>, String) {
        let mut spin = spinner();
        spin.start("Verifying your password...");
        // must verify that the password is good
        let (former_auth_key, symm_key) =
            User::rebuild_secret(old_password, self.clear_salt.clone());

        if symm_key == self.symmetric_key {
            spin.stop("Your password is valid");

            let (hash, salt) = crypto::hash_password(new_password, None);

            // user kdf to derive auth and symm key
            let (auth_key, symm_key) = crypto::kdf(hash);

            let master_key = DataAsset {
                asset: self.master_key.clone().asset,
                nonce: None,
                status: Some(DataStatus::Decrypted),
            };

            (
                Some(User {
                    uid: self.uid.clone(),                 // - still the same
                    username: self.username.to_string(),   // - still the same
                    symmetric_key: symm_key,               // + changed
                    clear_salt: Some(salt),                // + changed
                    master_key: master_key,                // - still the same
                    auth_key: Some(auth_key),              // + changed
                    public_key: self.public_key.clone(),   // - still the same
                    private_key: self.private_key.clone(), // - still the same
                    shared_to_me: self.shared_to_me.clone(),
                    shared_to_others: self.shared_to_others.clone(),
                }),
                bs58::encode(former_auth_key).into_string(),
            )
        } else {
            spin.stop("Invalid credentials");

            // invalid password
            (None, "".to_string())
        }
    }

    pub fn to_string(&self) -> String {
        // !!! The output contains secret key materials
        serde_json::to_string_pretty(&self).unwrap_or(String::from("Unable to display the user"))
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
