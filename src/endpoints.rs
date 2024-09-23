use std::error::Error;

use cliclack::{
    log::{self},
    spinner,
};
use reqwest::{Client, StatusCode};

use crate::models::{
    fs_entity::{FsEntity, PublicKeyMaterial},
    sharing::Sharing,
    user::User,
};

static URL: &str = "http://127.0.0.1:8080";

pub async fn sign_up(username: &str, password: &str) -> Result<Option<String>, Box<dyn Error>> {
    let client = Client::new();
    let mut spin = spinner();
    spin.start("Connnecting...");
    // create the user -> contains secret content
    let mut new_plain_user = User::generate(username, password)?;
    new_plain_user.encrypt()?;

    match client
        .get(format!("{}/get_sign_up", URL.to_string()))
        .json(&new_plain_user)
        .send()
        .await
    {
        Ok(res) => match res.status() {
            StatusCode::CREATED => {
                spin.stop("Account successfully created");

                let jwt = res.text().await.unwrap();

                Ok(Some(jwt))
            }
            _ => Ok({
                spin.stop("Error while creating your account");

                log::error(format!(
                    "{}",
                    match res.text().await {
                        Ok(t) => t,
                        Err(e) => e.to_string(),
                    }
                ))
                .unwrap();
                None
            }),
        },
        Err(e) => Ok({
            spin.stop("Error while creating your account");

            log::error(format!("{}", e.to_string())).unwrap();
            None
        }),
    }
}

pub async fn update_password(
    auth_token: &str,
    updated_user: &User,
    former_auth_key: &str,
) -> Option<String> {
    let client = Client::new();

    // create the user -> contains secret content
    let mut spin = spinner();
    spin.start("Updating your password...");

    match client
        .post(format!(
            "{}/auth/update_password?auth_token={}&former_auth_key={}",
            URL.to_string(),
            auth_token,
            former_auth_key
        ))
        .json(&updated_user)
        .send()
        .await
    {
        Ok(res) => match res.status() {
            StatusCode::OK => {
                spin.stop("Password updated successfully");
                Some("Password updated successfully".to_string())
            }
            _ => {
                spin.stop("Error while updating your password");

                log::error(format!(
                    "{}",
                    match res.text().await {
                        Ok(t) => t,
                        Err(e) => e.to_string(),
                    }
                ))
                .unwrap();
                None
            }
        },
        Err(e) => {
            spin.stop("Error while updating your password");

            log::error(format!("{}", e.to_string())).unwrap();
            None
        }
    }
}

pub async fn sign_in(username: &str, auth_key: Vec<u8>) -> Option<String> {
    let client = Client::new();
    let mut spin = spinner();
    spin.start("Connecting...");
    match client
        .get(format!(
            "{}/get_sign_in?username={}&auth_key={}",
            URL.to_string(),
            username,
            bs58::encode(auth_key).into_string()
        ))
        .send()
        .await
    {
        Ok(res) => match res.status() {
            StatusCode::OK => {
                spin.stop("Signed in your account successfully");
                let jwt = res.text().await.unwrap();

                Some(jwt)
            }
            _ => {
                log::error(format!(
                    "{}",
                    match res.text().await {
                        Ok(t) => t,
                        Err(e) => e.to_string(),
                    }
                ))
                .unwrap();
                None
            }
        },
        Err(e) => {
            log::error(format!(" {}", e.to_string())).unwrap();
            None
        }
    }
}

pub async fn get_user(auth_token: &str) -> Option<User> {
    let client = Client::new();
    let mut spin = spinner();
    spin.start("Fetching your details...");
    match client
        .get(format!(
            "{}/get_user?auth_token={}",
            URL.to_string(),
            auth_token,
        ))
        .send()
        .await
    {
        Ok(res) => match res.status() {
            StatusCode::OK => {
                spin.stop("Details successfully fetched");
                let expected_user: User =
                    match serde_json::from_str(res.text().await.unwrap().as_str()) {
                        Ok(c) => c,
                        Err(e) => {
                            log::error(format!("{}", e.to_string())).unwrap();
                            return None;
                        }
                    };
                Some(expected_user)
            }
            _ => {
                spin.stop("Error while fetching details");
                log::error(format!(
                    "{}",
                    match res.text().await {
                        Ok(t) => t,
                        Err(e) => e.to_string(),
                    }
                ))
                .unwrap();
                None
            }
        },
        Err(e) => {
            spin.stop("Error while fetching details");

            log::error(format!("{}", e.to_string())).unwrap();
            None
        }
    }
}

pub async fn get_salt(username: &str) -> Option<Vec<u8>> {
    let client = Client::new();
    let mut spin = spinner();
    spin.start("🧂 Fetching your salt...");

    match client
        .get(format!(
            "{}/auth/get_salt?username={}",
            URL.to_string(),
            username,
        ))
        .send()
        .await
    {
        Ok(res) => match res.status() {
            StatusCode::OK => {
                spin.stop("🧂 Salt successfully fetched");
                let clear_salt = res.text().await.unwrap();
                let salt = bs58::decode(clear_salt).into_vec();

                return Some(salt.unwrap());
            }
            _ => {
                // any other ->
                log::error("Error while fetching salt").unwrap();

                /* log::error(format!(
                    "{}",
                    match res.text().await {
                        Ok(t) => t,
                        Err(e) => e.to_string(),
                    }
                ))
                .unwrap(); */
                None
            }
        },
        Err(e) => {
            spin.stop("Error while fetching salt");

            log::error(format!("{}", e.to_string())).unwrap();
            None
        }
    }
}

pub async fn get_file(jwt: &str, file_id: &str, owner_id: &str) -> Option<Vec<u8>> {
    let client = Client::new();
    let mut spin = spinner();
    spin.start("Fetching file content...");
    match client
        .get(format!(
            "{}/file/get_content?auth_token={}&file_id={}&owner_id={}",
            URL.to_string(),
            jwt,
            file_id,
            owner_id
        ))
        .send()
        .await
    {
        Ok(res) => match res.status() {
            StatusCode::OK => {
                spin.stop("File content successfully fetched");

                let file_content = res.text().await.unwrap();
                let content = bs58::decode(file_content).into_vec();

                return Some(content.unwrap());
            }
            _ => {
                spin.stop("Error while fetching file content");

                // any other ->
                log::error(format!(
                    "{}",
                    match res.text().await {
                        Ok(t) => t,
                        Err(e) => e.to_string(),
                    }
                ))
                .unwrap();
                None
            }
        },
        Err(e) => {
            spin.stop("Error while fetching file content");

            log::error(format!("{}", e.to_string())).unwrap();
            None
        }
    }
}

pub async fn get_public_key_with_uid(
    auth_token: &str,
    username: &str,
) -> Option<PublicKeyMaterial> {
    let client = Client::new();
    let mut spin = spinner();
    spin.start("Fetching public key...");
    match client
        .get(format!(
            "{}/auth/get_public_key?auth_token={}&username={}",
            URL.to_string(),
            auth_token,
            username,
        ))
        .send()
        .await
    {
        Ok(res) => match res.status() {
            StatusCode::OK => {
                spin.stop("Public key successfully fetched");

                // the public key is encoded in base64
                let pk_material = res.text().await.unwrap();

                let decoded: PublicKeyMaterial = serde_json::from_str(&pk_material).unwrap();

                return Some(decoded);
            }
            _ => {
                spin.stop("Error while fetching public key");

                // any other ->
                log::error(format!(
                    "{}",
                    match res.text().await {
                        Ok(t) => t,
                        Err(e) => e.to_string(),
                    }
                ))
                .unwrap();
                None
            }
        },
        Err(e) => {
            spin.stop("Error while fetching public key");

            log::error(format!("{}", e.to_string())).unwrap();
            None
        }
    }
}

pub async fn share_entity(auth_token: &str, share: &Sharing) -> Option<String> {
    let client = Client::new();

    let mut spin = spinner();
    spin.start("Sharing content...");
    match client
        .post(format!(
            "{}/share?auth_token={}",
            URL.to_string(),
            auth_token,
        ))
        .json(share)
        .send()
        .await
    {
        Ok(res) => match res.status() {
            StatusCode::OK => {
                spin.stop("Element successfully shared");
                return Some(res.text().await.unwrap());
            }
            _ => {
                spin.stop("Error while sharing element");

                // any other ->
                log::error(format!(
                    "{}",
                    match res.text().await {
                        Ok(t) => t,
                        Err(e) => e.to_string(),
                    }
                ))
                .unwrap();
                None
            }
        },
        Err(e) => {
            spin.stop("Error while sharing element");

            log::error(format!("{}", e.to_string())).unwrap();
            None
        }
    }
}

pub async fn revoke_share(auth_token: &str, share: &Sharing) -> Option<String> {
    let client = Client::new();

    let mut spin = spinner();
    spin.start("Revoking share");
    match client
        .post(format!(
            "{}/revoke_share?auth_token={}",
            URL.to_string(),
            auth_token,
        ))
        .json(share)
        .send()
        .await
    {
        Ok(res) => match res.status() {
            StatusCode::OK => {
                spin.stop("Share succesfully revoked");

                return Some(res.text().await.unwrap());
            }
            _ => {
                spin.stop("Error while revoking share");

                // any other ->
                log::error(format!(
                    "{}",
                    match res.text().await {
                        Ok(t) => t,
                        Err(e) => e.to_string(),
                    }
                ))
                .unwrap();
                None
            }
        },
        Err(e) => {
            spin.stop("Error while revoking share");

            log::error(format!("{}", e.to_string())).unwrap();
            None
        }
    }
}

/// The path set must be encrypted
pub async fn add_file(auth_token: &str, new_file: &FsEntity) -> Option<String> {
    let client = Client::new();
    let mut spin = spinner();
    spin.start("Uploading new file...");
    match client
        .post(format!(
            "{}/file/create?auth_token={}",
            URL.to_string(),
            auth_token,
        ))
        .json(&new_file)
        .send()
        .await
    {
        Ok(res) => match res.status() {
            StatusCode::OK => {
                spin.stop("File successfully uploaded");

                return Some(res.text().await.unwrap());
            }
            _ => {
                spin.stop("Error while uploading file");

                // any other ->
                log::error(format!(
                    "{}",
                    match res.text().await {
                        Ok(t) => t,
                        Err(e) => e.to_string(),
                    }
                ))
                .unwrap();
                None
            }
        },
        Err(e) => {
            spin.stop("Error while uploading file");

            log::error(format!("{}", e.to_string())).unwrap();
            None
        }
    }
}

pub async fn create_dir(auth_token: &str, dir: &FsEntity) -> Option<String> {
    let client = Client::new();
    let mut spin = spinner();
    spin.start("Creating new directory...");
    match client
        .post(format!(
            "{}/dir/create?auth_token={}",
            URL.to_string(),
            auth_token,
        ))
        .json(dir)
        .send()
        .await
    {
        Ok(res) => match res.status() {
            StatusCode::OK => {
                spin.stop("Directory successfully created");
                return Some(res.text().await.unwrap());
            }
            _ => {
                spin.stop("Error while creating directory");

                // any other ->
                log::error(format!(
                    "{}",
                    match res.text().await {
                        Ok(t) => t,
                        Err(e) => e.to_string(),
                    }
                ))
                .unwrap();
                None
            }
        },
        Err(e) => {
            spin.stop("Error while creating directory");

            log::error(format!("{}", e.to_string())).unwrap();
            None
        }
    }
}

pub async fn get_children(auth_token: &str, parent_id: &str) -> Option<Vec<FsEntity>> {
    let client = Client::new();
    let mut spin = spinner();
    spin.start("Fetching directory children...");
    match client
        .get(format!(
            "{}/dirs/get_children?auth_token={}&parent_id={}",
            URL.to_string(),
            auth_token,
            parent_id
        ))
        .send()
        .await
    {
        Ok(res) => match res.status() {
            StatusCode::OK => {
                let list_dirs_str: Vec<FsEntity> =
                    serde_json::from_str(&res.text().await.unwrap()).unwrap();

                spin.stop(format!("{} children fetched", list_dirs_str.len()));

                return Some(list_dirs_str);
            }
            _ => {
                spin.stop("Error while fetching directory children");

                // any other ->
                log::error(format!(
                    "{}",
                    match res.text().await {
                        Ok(t) => t,
                        Err(e) => e.to_string(),
                    }
                ))
                .unwrap();
                None
            }
        },
        Err(e) => {
            spin.stop("Error while fetching directory children");

            log::error(format!("{}", e.to_string())).unwrap();
            None
        }
    }
}

pub async fn get_shared_children(
    auth_token: &str,
    share: &Sharing,
    sub_id: &str,
) -> Option<Vec<FsEntity>> {
    let client = Client::new();
    let mut spin = spinner();
    spin.start("Fetching directory children...");
    match client
        .get(format!(
            "{}/dirs/get_shared_children?auth_token={}&sub_entity_id={}",
            URL.to_string(),
            auth_token,
            sub_id
        ))
        .json(share)
        .send()
        .await
    {
        Ok(res) => match res.status() {
            StatusCode::OK => {
                let list_dirs_str: Vec<FsEntity> =
                    serde_json::from_str(&res.text().await.unwrap()).unwrap();
                spin.stop(format!("{} children fetched", list_dirs_str.len()));

                return Some(list_dirs_str);
            }
            _ => {
                spin.stop("Error while fetching directory children");

                // any other ->
                log::error(format!(
                    "{}",
                    match res.text().await {
                        Ok(t) => t,
                        Err(e) => e.to_string(),
                    }
                ))
                .unwrap();
                None
            }
        },
        Err(e) => {
            spin.stop("Error while fetching directory children");

            log::error(format!("{}", e.to_string())).unwrap();
            None
        }
    }
}

pub async fn get_shared_entity(
    auth_token: &str,
    share: &Sharing,
) -> Result<FsEntity, Box<dyn Error>> {
    let client = Client::new();
    let mut spin = spinner();
    spin.start("Fetching element...");
    let Ok(res) = client
        .get(format!(
            "{}/get_shared_entity?auth_token={}",
            URL.to_string(),
            auth_token,
        ))
        .json(share)
        .send()
        .await
    else {
        return Err("Cannot reach the server".into());
    };

    let status = res.status();

    let Ok(content) = res.text().await else {
        return Err("Unable to fetch request content".into());
    };

    if status != StatusCode::OK {
        // any other ->
        log::error(format!("{}", content)).unwrap();
    }
    // only for ok
    spin.stop("Element successfully fetched");

    let fetched_dir: FsEntity = serde_json::from_str(&content)?;

    // not ok
    spin.stop("Error while fetching your element");

    return Ok(fetched_dir);
}
