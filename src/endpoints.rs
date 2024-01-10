use reqwest::{Client, StatusCode};

use crate::model::{DataAsset, FileEntity, FsTree, User};

static URL: &str = "http://localhost:8000";

// Todo get back the created user with jwt
pub async fn sign_up(username: &str, password: &str) -> (Option<String>, Option<User>) {
    // create the user -> contains secret content
    let new_plain_user = User::generate(username, password);

    let client = Client::new();

    match client
        .get(format!("{}/get_sign_up", URL.to_string()))
        .json(&new_plain_user.clone().encrypt())
        .send()
        .await
    {
        Ok(res) => match res.status() {
            StatusCode::CREATED => {
                println!("I went there");

                let jwt = res.text().await.unwrap();

                (Some(jwt), Some(new_plain_user))
            }
            _ => {
                println!(
                    "Error : {}",
                    match res.text().await {
                        Ok(t) => t,
                        Err(e) => e.to_string(),
                    }
                );
                (None, None)
            }
        },
        Err(e) => {
            println!("Error : {}", e.to_string());
            (None, None)
        }
    }
}

/// Use to fetch encrypted tree metadata of the user
pub async fn get_my_tree(auth_token: &str) -> Option<FsTree> {
    let client = Client::new();

    match client
        .get(format!(
            "{}/get_my_tree?auth_token={}",
            URL.to_string(),
            auth_token
        ))
        .send()
        .await
    {
        Ok(res) => match res.status() {
            StatusCode::OK => {
                let my_tree: FsTree =
                    serde_json::from_str(res.text().await.unwrap().as_str()).unwrap();
                Some(my_tree)
            }
            _ => {
                // any other ->
                println!(
                    "Error : {}",
                    match res.text().await {
                        Ok(t) => t,
                        Err(e) => e.to_string(),
                    }
                );
                None
            }
        },
        Err(e) => {
            println!("Error : {}", e.to_string());
            None
        }
    }
}

pub async fn get_file(auth_token: &str, mut expected_file: FileEntity) -> Option<FileEntity> {
    let client = Client::new();

    let path = expected_file.clone().path;

    match client
        .get(format!(
            "{}/file/get?token={}?path={}",
            URL.to_string(),
            auth_token,
            path
        ))
        .send()
        .await
    {
        Ok(res) => match res.status() {
            StatusCode::OK => {
                // fetch the content
                let encrypted_content: DataAsset =
                    serde_json::from_str(res.text().await.unwrap().as_str()).unwrap();

                expected_file.content = encrypted_content;
                Some(expected_file)
            }
            _ => {
                // any other ->
                println!(
                    "Error : {}",
                    match res.text().await {
                        Ok(t) => t,
                        Err(e) => e.to_string(),
                    }
                );
                None
            }
        },
        Err(e) => {
            println!("Error : {}", e.to_string());
            None
        }
    }
}

pub async fn get_salt(auth_key: &str, username: &str) -> Option<String> {
    let client = Client::new();

    match client
        .get(format!(
            "{}/auth/get_salt?username={}?auth_key={}",
            URL.to_string(),
            username,
            auth_key
        ))
        .send()
        .await
    {
        Ok(res) => match res.status() {
            StatusCode::OK => {
                let clear_salt = res.text().await.unwrap();
                return Some(clear_salt);
            }
            _ => {
                // any other ->
                println!(
                    "Error : {}",
                    match res.text().await {
                        Ok(t) => t,
                        Err(e) => e.to_string(),
                    }
                );
                None
            }
        },
        Err(e) => {
            println!("Error : {}", e.to_string());
            None
        }
    }
}

pub async fn get_public_key(auth_token: &str, username: &str) -> Option<Vec<u8>> {
    let client = Client::new();

    match client
        .get(format!(
            "{}/auth/get_public_key?username={}?auth_token={}",
            URL.to_string(),
            username,
            auth_token
        ))
        .send()
        .await
    {
        Ok(res) => match res.status() {
            StatusCode::OK => {
                // the public key is encoded in base64
                let b64_public_key = res.text().await.unwrap();
                let public_key = bs58::decode(b64_public_key).into_vec().unwrap();

                return Some(public_key);
            }
            _ => {
                // any other ->
                println!(
                    "Error : {}",
                    match res.text().await {
                        Ok(t) => t,
                        Err(e) => e.to_string(),
                    }
                );
                None
            }
        },
        Err(e) => {
            println!("Error : {}", e.to_string());
            None
        }
    }
}

pub async fn share_entity(
    auth_token: &str,
    path_2_share: &str,
    username: &str,
    encrypted_key: Vec<u8>,
) -> Option<String> {
    let client = Client::new();

    let b64_encrypted_key = bs58::encode(encrypted_key).into_string();

    match client
        .get(format!(
            "{}/share/username={}?auth_token={}?path={}?shared_key={}",
            URL.to_string(),
            username,
            auth_token,
            path_2_share,
            b64_encrypted_key
        ))
        .send()
        .await
    {
        Ok(res) => match res.status() {
            StatusCode::OK => {
                return Some(res.text().await.unwrap());
            }
            _ => {
                // any other ->
                println!(
                    "Error : {}",
                    match res.text().await {
                        Ok(t) => t,
                        Err(e) => e.to_string(),
                    }
                );
                None
            }
        },
        Err(e) => {
            println!("Error : {}", e.to_string());
            None
        }
    }
}

/// The path set must be encrypted
pub async fn create_file(auth_token: &str, new_file: FileEntity) -> Option<String> {
    let client = Client::new();
    let serialised_file = serde_json::to_string(&new_file).unwrap();
    match client
        .get(format!(
            "{}/file/create/auth_token={}",
            URL.to_string(),
            auth_token,
        ))
        .json(&serialised_file)
        .send()
        .await
    {
        Ok(res) => match res.status() {
            StatusCode::OK => {
                return Some(res.text().await.unwrap());
            }
            _ => {
                // any other ->
                println!(
                    "Error : {}",
                    match res.text().await {
                        Ok(t) => t,
                        Err(e) => e.to_string(),
                    }
                );
                None
            }
        },
        Err(e) => {
            println!("Error : {}", e.to_string());
            None
        }
    }
}

pub fn create_dir(path: &str) {}
