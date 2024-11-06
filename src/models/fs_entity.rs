use std::error::Error;

use cliclack::spinner;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, NoneAsEmptyString};

use crate::{crypto, models::misc::base58};

use super::data_asset::{DataAsset, DataState};

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
            None,
        )?;

        let encrypted_key = crypto::encrypt(parent_key.clone(), self.key.clone().asset, None)?;

        let mut encrypted_content: Option<DataAsset> = None;

        if self.entity_type == "file" {
            // if it is a file it must be encrypted with its own key
            encrypted_content = match crypto::encrypt(
                self.key.asset.clone().unwrap(), // for a file the content
                self.content.clone().unwrap().asset,
                None,
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
