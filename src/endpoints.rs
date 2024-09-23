use std::error::Error;

use cliclack::{
    log::{self},
    spinner,
};
use once_cell::sync::Lazy;
use reqwest::{Client, StatusCode};

use crate::models::{
    fs_entity::{FsEntity, PublicKeyMaterial},
    sharing::Sharing,
    user::User,
};

static URL: &str = "http://127.0.0.1:8080";

static CLIENT: Lazy<Client> = Lazy::new(|| Client::new());

pub async fn sign_up(username: &str, password: &str) -> Result<Option<String>, Box<dyn Error>> {
    let mut spin = spinner();
    spin.start("Connnecting...");
    // create the user -> contains secret content
    let mut new_plain_user = User::generate(username, password)?;
    new_plain_user.encrypt()?;

    let Ok(res) = CLIENT
        .get(format!("{}/get_sign_up", URL.to_string()))
        .json(&new_plain_user)
        .send()
        .await
    else {
        spin.stop("Error while creating your account");

        return Err("Error while creating your account".into());
    };

    let StatusCode::CREATED = res.status() else {
        spin.stop("Error while creating your account");
        log::error(format!(
            "{}",
            match res.text().await {
                Ok(t) => t,
                Err(e) => e.to_string(),
            }
        ))
        .unwrap();
        return Ok(None);
    };

    spin.stop("Account successfully created");
    let jwt = res.text().await.unwrap();
    Ok(Some(jwt))
}

pub async fn update_password(
    auth_token: &str,
    updated_user: &User,
    former_auth_key: &str,
) -> Option<String> {
    // create the user -> contains secret content
    let mut spin = spinner();
    spin.start("Updating your password...");

    let Ok(res) = CLIENT
        .post(format!(
            "{}/auth/update_password&former_auth_key={}",
            URL.to_string(),
            former_auth_key
        ))
        .bearer_auth(auth_token)
        .json(&updated_user)
        .send()
        .await
    else {
        spin.stop("Error while updating your password");

        return None;
    };

    let StatusCode::OK = res.status() else {
        spin.stop("Error while updating your password");

        log::error(format!(
            "{}",
            match res.text().await {
                Ok(t) => t,
                Err(e) => e.to_string(),
            }
        ))
        .unwrap();
        return None;
    };

    spin.stop("Password updated successfully");
    Some("Password updated successfully".to_string())
}

pub async fn sign_in(username: &str, auth_key: Vec<u8>) -> Option<String> {
    let mut spin = spinner();
    spin.start("Connecting...");

    let Ok(res) = CLIENT
        .get(format!(
            "{}/get_sign_in?username={}&auth_key={}",
            URL.to_string(),
            username,
            bs58::encode(auth_key).into_string()
        ))
        .send()
        .await
    else {
        return None;
    };

    let StatusCode::OK = res.status() else {
        log::error(format!(
            "{}",
            match res.text().await {
                Ok(t) => t,
                Err(e) => e.to_string(),
            }
        ))
        .unwrap();
        return None;
    };
    spin.stop("Signed in your account successfully");
    let jwt = res.text().await.unwrap();

    Some(jwt)
}

pub async fn get_user(auth_token: &str) -> Option<User> {
    let mut spin = spinner();
    spin.start("Fetching your details...");
    let Ok(res) = CLIENT
        .get(format!("{}/get_user", URL.to_string(),))
        .bearer_auth(auth_token)
        .send()
        .await
    else {
        spin.stop("Error while fetching details");

        return None;
    };
    let StatusCode::OK = res.status() else {
        spin.stop("Error while fetching details");
        log::error(format!(
            "{}",
            match res.text().await {
                Ok(t) => t,
                Err(e) => e.to_string(),
            }
        ))
        .unwrap();
        spin.stop("Error while fetching details");

        return None;
    };

    let Ok(expected_user) = serde_json::from_str(res.text().await.unwrap().as_str()) else {
        return None;
    };

    spin.stop("Details successfully fetched");

    Some(expected_user)
}

pub async fn get_salt(username: &str) -> Option<Vec<u8>> {
    let mut spin = spinner();
    spin.start("🧂 Fetching your salt...");

    let Ok(res) = CLIENT
        .get(format!(
            "{}/auth/get_salt?username={}",
            URL.to_string(),
            username,
        ))
        .send()
        .await
    else {
        spin.stop("Error while fetching salt");
        return None;
    };

    let StatusCode::OK = res.status() else {
        log::error("Error while fetching salt").unwrap();
        return None;
    };
    spin.stop("🧂 Salt successfully fetched");
    let clear_salt = res.text().await.unwrap();
    let salt = bs58::decode(clear_salt).into_vec();

    Some(salt.unwrap())
}

pub async fn get_file(jwt: &str, file_id: &str, owner_id: &str) -> Option<Vec<u8>> {
    let mut spin = spinner();
    spin.start("Fetching file content...");

    let Ok(res) = CLIENT
        .get(format!(
            "{}/file/get_content?file_id={}&owner_id={}",
            URL.to_string(),
            file_id,
            owner_id
        ))
        .bearer_auth(jwt)
        .send()
        .await
    else {
        spin.stop("Error while fetching file content");
        return None;
    };

    let StatusCode::OK = res.status() else {
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
        return None;
    };
    spin.stop("File content successfully fetched");

    let file_content = res.text().await.unwrap();
    let content = bs58::decode(file_content).into_vec();

    Some(content.unwrap())
}

pub async fn get_public_key_with_uid(
    auth_token: &str,
    username: &str,
) -> Option<PublicKeyMaterial> {
    let mut spin = spinner();
    spin.start("Fetching public key...");

    let Ok(res) = CLIENT
        .get(format!(
            "{}/auth/get_public_key&username={}",
            URL.to_string(),
            username,
        ))
        .bearer_auth(auth_token)
        .send()
        .await
    else {
        spin.stop("Error while fetching public key");

        return None;
    };

    let StatusCode::OK = res.status() else {
        spin.stop("Error while fetching public key");
        return None;
    };

    let pk_material = res.text().await.unwrap();

    let decoded: PublicKeyMaterial = serde_json::from_str(&pk_material).unwrap();

    Some(decoded)
}

pub async fn share_entity(auth_token: &str, share: &Sharing) -> Option<String> {
    let mut spin = spinner();
    spin.start("Sharing content...");

    let Ok(res) = CLIENT
        .post(format!("{}/share", URL.to_string(),))
        .bearer_auth(auth_token)
        .json(share)
        .send()
        .await
    else {
        spin.stop("Error while sharing element");

        return None;
    };

    let StatusCode::OK = res.status() else {
        log::error(format!(
            "{}",
            match res.text().await {
                Ok(t) => t,
                Err(e) => e.to_string(),
            }
        ))
        .unwrap();
        return None;
    };

    spin.stop("Element successfully shared");

    Some(res.text().await.unwrap())
}

pub async fn revoke_share(auth_token: &str, share: &Sharing) -> Option<String> {
    let mut spin = spinner();
    spin.start("Revoking share");

    let Ok(res) = CLIENT
        .post(format!("{}/revoke_share", URL.to_string()))
        .bearer_auth(auth_token)
        .json(share)
        .send()
        .await
    else {
        spin.stop("Error while revoking share");

        return None;
    };

    let StatusCode::OK = res.status() else {
        spin.stop("Error while revoking share");
        log::error(format!(
            "{}",
            match res.text().await {
                Ok(t) => t,
                Err(e) => e.to_string(),
            }
        ))
        .unwrap();
        return None;
    };

    spin.stop("Share succesfully revoked");

    return Some(res.text().await.unwrap());
}

/// The path set must be encrypted
pub async fn add_file(auth_token: &str, new_file: &FsEntity) -> Option<String> {
    let mut spin = spinner();
    spin.start("Uploading new file...");

    let Ok(res) = CLIENT
        .post(format!("{}/file/create", URL.to_string(),))
        .bearer_auth(auth_token)
        .json(&new_file)
        .send()
        .await
    else {
        spin.stop("Error while uploading file");
        return None;
    };

    let StatusCode::OK = res.status() else {
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
        return None;
    };

    spin.stop("File successfully uploaded");

    Some(res.text().await.unwrap())
}

pub async fn create_dir(auth_token: &str, dir: &FsEntity) -> Option<String> {
    let mut spin = spinner();
    spin.start("Creating new directory...");

    let Ok(res) = CLIENT
        .post(format!("{}/dir/create", URL.to_string(),))
        .bearer_auth(auth_token)
        .json(dir)
        .send()
        .await
    else {
        spin.stop("Error while creating directory");

        return None;
    };

    let StatusCode::OK = res.status() else {
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
        return None;
    };

    spin.stop("Directory successfully created");

    Some(res.text().await.unwrap())
}

pub async fn get_children(auth_token: &str, parent_id: &str) -> Option<Vec<FsEntity>> {
    let mut spin = spinner();
    spin.start("Fetching directory children...");

    let Ok(res) = CLIENT
        .get(format!(
            "{}/dirs/get_children?parent_id={}",
            URL.to_string(),
            parent_id
        ))
        .bearer_auth(auth_token)
        .send()
        .await
    else {
        spin.stop("Error while fetching directory children");
        return None;
    };

    let StatusCode::OK = res.status() else {
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
        return None;
    };

    let list_dirs_str: Vec<FsEntity> = serde_json::from_str(&res.text().await.unwrap()).unwrap();

    spin.stop(format!("{} children fetched", list_dirs_str.len()));

    Some(list_dirs_str)
}

pub async fn get_shared_children(
    auth_token: &str,
    share: &Sharing,
    sub_id: &str,
) -> Option<Vec<FsEntity>> {
    let mut spin = spinner();
    spin.start("Fetching directory children...");

    let Ok(res) = CLIENT
        .get(format!(
            "{}/dirs/get_shared_children?sub_entity_id={}",
            URL.to_string(),
            sub_id
        ))
        .bearer_auth(auth_token)
        .json(share)
        .send()
        .await
    else {
        spin.stop("Error while fetching directory children");

        return None;
    };

    let StatusCode::OK = res.status() else {
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
        return None;
    };

    let list_dirs_str: Vec<FsEntity> = serde_json::from_str(&res.text().await.unwrap()).unwrap();
    spin.stop(format!("{} children fetched", list_dirs_str.len()));

    Some(list_dirs_str)
}

pub async fn get_shared_entity(
    auth_token: &str,
    share: &Sharing,
) -> Result<FsEntity, Box<dyn Error>> {
    let mut spin = spinner();
    spin.start("Fetching element...");

    let Ok(res) = CLIENT
        .get(format!("{}/get_shared_entity", URL.to_string()))
        .bearer_auth(auth_token)
        .json(share)
        .send()
        .await
    else {
        return Err("Cannot reach the server".into());
    };

    let StatusCode::OK = res.status() else {
        return Err("Unable to fetch request content".into());
    };

    let Ok(content) = res.text().await else {
        return Err("Unable to fetch request content".into());
    };

    // only for ok
    spin.stop("Element successfully fetched");

    let fetched_dir: FsEntity = serde_json::from_str(&content)?;

    // not ok
    spin.stop("Error while fetching your element");

    return Ok(fetched_dir);
}
