use crate::models::misc::base58;
use serde::{Deserialize, Serialize};

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
