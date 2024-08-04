use cliclack::spinner;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, NoneAsEmptyString};
use std::error::Error;

use crate::crypto;
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone, Copy)]
pub enum DataState {
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
    pub state: Option<DataState>,
}

impl DataAsset {
    pub fn encrypted(asset: Option<Vec<u8>>, nonce: Option<Vec<u8>>) -> DataAsset {
        DataAsset {
            asset,
            nonce,
            state: Some(DataState::Encrypted),
        }
    }

    pub fn decrypted(asset: Option<Vec<u8>>, nonce: Option<Vec<u8>>) -> DataAsset {
        DataAsset {
            asset,
            nonce,
            state: Some(DataState::Decrypted),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Sharing {
    #[serde(with = "base58")]
    pub key: Option<Vec<u8>>,
    pub entity_uid: String, // shared entity
    pub owner_id: String,   // owner that shared the entity
    pub user_id: String,    // User id I share with
}

impl Sharing {
    pub fn new(
        key: Option<Vec<u8>>,
        entity_uid: String,
        owner_id: String,
        user_id: String,
    ) -> Self {
        Sharing {
            key,
            entity_uid,
            owner_id,
            user_id,
        }
    }
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
    pub fn new(
        uid: Option<String>,
        parent_id: Option<String>,
        name: DataAsset,
        path: String,
        key: DataAsset,
        entity_type: String,
        content: Option<DataAsset>,
    ) -> Self {
        FsEntity {
            uid,
            parent_id,
            path,
            name,
            key,
            content,
            entity_type,
        }
    }

    // Before all must provide the current
    pub fn create(
        name: &str,
        path: &str,
        content: Option<Vec<u8>>,
        parent_id: &str,
    ) -> Result<FsEntity, Box<dyn Error>> {
        let dir_key = crypto::generate_master_key()?;
        let mut content_2_process: Option<DataAsset> = None;

        let entity_type = if content.is_none() {
            // if it s a dir
            String::from("dir")
        } else {
            // else we create the content
            content_2_process = Some(DataAsset {
                asset: content,
                nonce: None,
                state: Some(DataState::Decrypted),
            });
            String::from("file")
        };

        let created_entity = FsEntity::new(
            None,
            Some(parent_id.to_string()),
            DataAsset::decrypted(Some(name.as_bytes().to_vec()), None),
            path.to_string(),
            DataAsset::decrypted(Some(dir_key), None),
            entity_type,
            content_2_process,
        );

        Ok(created_entity)
    }

    // symm key used is the parent dir key
    pub fn encrypt(&mut self, parent_key: Vec<u8>) -> Result<(), Box<dyn Error>> {
        let mut spin = spinner();
        spin.start(format!("Encrypting {}...", self.entity_type));
        // if the dir has already been encrypted a time, use the nonce to reencrypt
        let encrypted_name = crypto::encrypt(
            self.key.clone().asset.unwrap(),
            self.name.asset.clone(),
            self.name.nonce.clone(),
        )?;

        let encrypted_key = crypto::encrypt(
            parent_key.clone(),
            self.key.clone().asset,
            self.key.clone().nonce,
        )?;

        let mut encrypted_content: Option<DataAsset> = None;

        if self.entity_type == "file" {
            // if it is a file it must be encrypted with its own key
            encrypted_content = match crypto::encrypt(
                self.key.asset.clone().unwrap(), // for a file the content
                self.content.clone().unwrap().asset,
                self.content.clone().unwrap().nonce,
            ) {
                Ok(ciphertext) => Some(ciphertext),
                Err(_) => None,
            };
        }

        spin.stop(format!("{} successfully encrypted", self.entity_type));
        self.name = encrypted_name;
        self.key = encrypted_key;
        self.content = encrypted_content;

        Ok(())
    }

    // happends when fetching tree from api so must be decrypted
    pub fn decrypt(&mut self, parent_key: Vec<u8>) -> Result<(), Box<dyn Error>> {
        let mut spin = spinner();
        spin.start(format!("Decrypting {}...", self.entity_type));
        // decrypt the entity key to decrypt the rest
        let decrypted_key = crypto::decrypt(
            parent_key.clone(),
            self.key.nonce.clone(),
            self.key.asset.clone(),
        )?;

        // decrpyted with own key
        let decrypted_name = crypto::decrypt(
            decrypted_key.clone(),
            self.name.nonce.clone(),
            self.name.asset.clone(),
        )?;

        // todo improve code quality
        let decrypted_content = if self.entity_type == "file" {
            let asset = match crypto::decrypt(
                decrypted_key.clone(),
                self.content.clone().unwrap().nonce.clone(),
                self.content.clone().unwrap().asset,
            ) {
                Ok(asset) => Some(asset),
                Err(_) => None,
            };

            Some(DataAsset::decrypted(
                asset,
                self.content.clone().unwrap().nonce.clone(),
            ))
        } else {
            None
        };

        // todo must be moved out there
        spin.stop(format!("{} successfully decrypted", self.entity_type));

        let name = DataAsset::decrypted(Some(decrypted_name), self.name.nonce.clone());

        let key = DataAsset::decrypted(Some(decrypted_key), self.key.nonce.clone());

        self.name = name;
        self.key = key;
        self.content = decrypted_content;

        Ok(())
    }

    pub fn decrypt_from_dir_key(&mut self, dir_key: Vec<u8>) -> Result<(), Box<dyn Error>> {
        // decrypt the entity key to decrypt the rest
        let mut spin = spinner();
        spin.start(format!("Decrypting {}...", self.entity_type));
        // decrpyted with own key
        let decrypted_name = crypto::decrypt(
            dir_key.clone(),
            self.name.nonce.clone(),
            self.name.asset.clone(),
        )
        .unwrap();

        let decrypted_content = if self.entity_type == "file" {
            let asset = match crypto::decrypt(
                dir_key.clone(),
                self.content.clone().unwrap().nonce.clone(),
                self.content.clone().unwrap().asset,
            ) {
                Ok(asset) => Some(asset),
                Err(_) => None,
            };

            Some(DataAsset::decrypted(
                asset,
                self.content.as_ref().unwrap().nonce.clone(),
            ))
        } else {
            None
        };

        spin.stop(format!("{} successfully decrypted", self.entity_type));

        let name = DataAsset::decrypted(Some(decrypted_name), self.name.nonce.clone());
        let key = DataAsset::decrypted(Some(dir_key), self.key.nonce.clone());

        self.name = name;
        self.key = key;
        self.content = decrypted_content;

        Ok(())
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
    pub fn new(
        uid: Option<String>,
        username: String,
        symmetric_key: Vec<u8>,
        clear_salt: Option<Vec<u8>>,
        master_key: DataAsset,
        auth_key: Option<Vec<u8>>,
        public_key: Option<Vec<u8>>,
        private_key: DataAsset,
        shared_to_me: Option<Vec<Sharing>>,
        shared_to_others: Option<Vec<Sharing>>,
    ) -> Self {
        User {
            uid,
            username,
            symmetric_key,
            clear_salt,
            master_key,
            auth_key,
            public_key,
            private_key,
            shared_to_me,
            shared_to_others,
        }
    }

    pub fn generate(username: &str, password: &str) -> Result<Self, Box<dyn Error>> {
        let mut spin = spinner();
        spin.start("Generating your keys");
        // generate the hash from password, give the hash and the salt
        let (hash, salt) = crypto::hash_password(password, None)?;

        // generate the master key
        let master_key = crypto::generate_master_key()?;

        // user kdf to derive auth and symm key
        let (auth_key, symm_key) = crypto::kdf(hash)?;

        // asymm crypto -> generate public and private keys
        let (private_key, public_key) = crypto::generate_asymm_keys()?;

        spin.stop("Keys successfully generated");
        let master_key = DataAsset::decrypted(Some(master_key), None);
        let private_key = DataAsset::decrypted(Some(private_key), None);

        let new_user = Self::new(
            None,
            username.to_string(),
            symm_key,
            Some(salt),
            master_key,
            Some(auth_key),
            Some(public_key),
            private_key,
            Some(Vec::new()),
            Some(Vec::new()),
        );

        Ok(new_user)
    }

    pub fn find_sharing_by_entity_id(&self, entity_id: &str) -> Result<Sharing, Box<dyn Error>> {
        let error_message = Err("No sharing found".into());

        let Some(share) = self
            .shared_to_others
            .as_ref()
            .unwrap_or(&Vec::new()) // avoid crash
            .iter()
            .find(|sharing| sharing.entity_uid == entity_id)
            .cloned()
        else {
            return error_message;
        };

        if share.entity_uid.is_empty() {
            return error_message;
        }

        Ok(share)
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

        if let Some(shared_to_others) = &mut self.shared_to_others {
            if !shared_to_others
                .iter()
                .any(|s| s.entity_uid == sharing.entity_uid)
            {
                shared_to_others.push(sharing.clone());
            }
        }
    }

    /// Use to rebuild symmetric and auth key from the password and the salt obtained by the api
    pub fn rebuild_secret(
        password: &str,
        salt: Option<Vec<u8>>,
    ) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
        let mut spin = spinner();

        spin.start("Rebuilding your keys...");
        // generate the hash from password, give the hash and the salt
        let (hash, _) = crypto::hash_password(password, salt)?;

        // user kdf to derive auth and symm key
        let (auth_key, symm_key) = crypto::kdf(hash)?;
        spin.stop("Keys successfully rebuilt");

        Ok((auth_key, symm_key))
    }

    pub fn encrypt(&mut self) -> Result<(), Box<dyn Error>> {
        let mut spin = spinner();
        spin.start("Encrypting your profile...");
        let symmetric_key = self.symmetric_key.clone();
        let mk = self.master_key.asset.clone();

        // encrypt the master and asymm private keys using symmetric key
        let encrypted_master_key = crypto::encrypt(
            symmetric_key.clone(),
            mk.clone(),
            self.master_key.nonce.clone(),
        )?;

        let encrypted_private_key = crypto::encrypt(
            mk.unwrap(),
            self.private_key.asset.clone(),
            self.private_key.nonce.clone(),
        )?;

        spin.stop("Profile successfully encrypted");

        self.master_key = encrypted_master_key;
        self.private_key = encrypted_private_key;

        Ok(())
    }

    pub fn erase_secret(&mut self) -> Result<(), Box<dyn Error>> {
        let empty = DataAsset::decrypted(None, None);

        self.uid = None;
        self.username = "".to_string();
        self.symmetric_key = Vec::new();
        self.clear_salt = None;
        self.master_key = empty.clone();
        self.auth_key = None;
        self.public_key = None;
        self.private_key = empty.clone();
        self.shared_to_others = None;
        self.shared_to_me = None;

        Ok(())
    }

    pub fn decrypt(&mut self, password: &str, salt: Option<Vec<u8>>) -> Result<(), Box<dyn Error>> {
        let mut spin = spinner();
        spin.start("Decrypting your profile...");
        // use the fetched salt to generate password hash
        let (password_hash, _) = crypto::hash_password(password, salt.clone())?;

        // retrieve user symm key using kdf from the password hash
        let (_, user_symm_key) = crypto::kdf(password_hash.try_into().unwrap_or_default())?;

        // decrypt the master key using user symm key
        let user_master_key = crypto::decrypt(
            user_symm_key.clone(),
            self.master_key.nonce.clone(),
            self.master_key.asset.clone(),
        )?;

        // decrypt the private asymm key using user symm key
        let user_private_key = crypto::decrypt(
            user_master_key.clone(),
            self.private_key.nonce.clone(),
            self.private_key.asset.clone(),
        )?;

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
        // we don't need it anymore as soon as we fetch and decrypted the content from the api
        let mk = DataAsset::decrypted(Some(user_master_key), self.master_key.nonce.clone());
        let pk = DataAsset::decrypted(Some(user_private_key), self.private_key.nonce.clone());

        // update filed with decrypted content
        self.symmetric_key = user_symm_key;
        self.master_key = mk;
        self.private_key = pk;

        Ok(())
    }

    // todo review, crash after changing
    pub fn update_password(
        &mut self,
        old_password: &str,
        new_password: &str,
    ) -> Result<String, Box<dyn Error>> {
        let mut spin = spinner();
        spin.start("Verifying your password...");
        // must verify that the password is good

        let (former_auth_key, symm_key) =
            User::rebuild_secret(old_password, self.clear_salt.clone())?;

        if symm_key != self.symmetric_key {
            spin.stop("Invalid credentials");

            // invalid password
            return Err("Invalid credentials".into());
        }

        spin.stop("Your password is valid");

        let (hash, salt) = crypto::hash_password(new_password, None)?;

        // user kdf to derive auth and symm key
        let (auth_key, symm_key) = crypto::kdf(hash)?;

        let master_key = DataAsset::decrypted(self.master_key.clone().asset, None);

        self.symmetric_key = symm_key;
        self.clear_salt = Some(salt);
        self.auth_key = Some(auth_key);
        self.master_key = master_key;

        return Ok(bs58::encode(former_auth_key).into_string());
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
