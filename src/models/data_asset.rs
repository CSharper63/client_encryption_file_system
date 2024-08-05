use serde::{Deserialize, Serialize};

use crate::models::misc::base58;

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
