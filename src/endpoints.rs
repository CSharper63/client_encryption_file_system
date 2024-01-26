use reqwest::{Client, StatusCode};

use model::User;

use crate::model::{self, FsEntity, PublicKeyMaterial, Sharing};

static URL: &str = "https://127.0.0.1:443";

// Todo get back the created user with jwt
pub async fn sign_up(username: &str, password: &str) -> Option<String> {
    let client = Client::new();

    // create the user -> contains secret content
    let new_plain_user = User::generate(username, password);

    println!("{}", new_plain_user.clone().to_string());

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

                Some(jwt)
            }
            _ => {
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

pub async fn update_password(
    auth_token: &str,
    updated_user: &User,
    former_auth_key: &str,
) -> Option<String> {
    let client = Client::new();

    // create the user -> contains secret content

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
            StatusCode::OK => Some("Password changed".to_string()),
            _ => {
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

pub async fn sign_in(username: &str, auth_key: Vec<u8>) -> Option<String> {
    let client = Client::new();
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
                let jwt = res.text().await.unwrap();

                Some(jwt)
            }
            _ => {
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

pub async fn get_user(auth_token: &str) -> Option<User> {
    let client = Client::new();
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
                let expected_user: User =
                    match serde_json::from_str(res.text().await.unwrap().as_str()) {
                        Ok(c) => c,
                        Err(e) => {
                            println!("Error while fetching user : {}", e.to_string());
                            return None;
                        }
                    };
                Some(expected_user)
            }
            _ => {
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

/// Use to fetch encrypted tree metadata of the user
/* pub async fn get_my_tree(auth_token: &str) -> Option<RootTree> {
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
                let my_tree: RootTree =
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
} */

/* pub async fn get_file(auth_token: &str, mut expected_file: FileEntity) -> Option<FileEntity> {
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
} */

pub async fn get_salt(username: &str) -> Option<Vec<u8>> {
    let client = Client::new();

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
                let clear_salt = res.text().await.unwrap();
                let salt = bs58::decode(clear_salt).into_vec();

                return Some(salt.unwrap());
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

pub async fn get_file(jwt: &str, file_id: &str, owner_id: &str) -> Option<Vec<u8>> {
    let client = Client::new();
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
                let file_content = res.text().await.unwrap();
                let content = bs58::decode(file_content).into_vec();

                return Some(content.unwrap());
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

pub async fn get_public_key_with_uid(
    auth_token: &str,
    username: &str,
) -> Option<PublicKeyMaterial> {
    let client = Client::new();

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
                // the public key is encoded in base64
                let pk_material = res.text().await.unwrap();

                let decoded: PublicKeyMaterial = serde_json::from_str(&pk_material).unwrap();

                return Some(decoded);
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

pub async fn share_entity(auth_token: &str, share: &Sharing) -> Option<String> {
    let client = Client::new();

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

pub async fn revoke_share(auth_token: &str, share: &Sharing) -> Option<String> {
    let client = Client::new();

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
pub async fn add_file(auth_token: &str, new_file: &FsEntity) -> Option<String> {
    let client = Client::new();

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

pub async fn create_dir(auth_token: &str, dir: &FsEntity) -> Option<String> {
    let client = Client::new();

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

pub async fn get_children(auth_token: &str, parent_id: &str) -> Option<Vec<FsEntity>> {
    let client = Client::new();

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

                return Some(list_dirs_str);
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

pub async fn get_shared_children(
    auth_token: &str,
    share: &Sharing,
    sub_id: &str,
) -> Option<Vec<FsEntity>> {
    let client = Client::new();

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

                return Some(list_dirs_str);
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

pub async fn get_shared_entity(auth_token: &str, share: &Sharing) -> Option<FsEntity> {
    let client = Client::new();

    match client
        .get(format!(
            "{}/get_shared_entity?auth_token={}",
            URL.to_string(),
            auth_token,
        ))
        .json(share)
        .send()
        .await
    {
        Ok(res) => match res.status() {
            StatusCode::OK => {
                let fetched_dir: FsEntity =
                    serde_json::from_str(&res.text().await.unwrap()).unwrap();

                return Some(fetched_dir);
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
