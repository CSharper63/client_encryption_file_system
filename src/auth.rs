use reqwest::{Client, StatusCode};

use crate::model::User;

static URL: &str = "http://localhost:8000";

pub async fn sign_up(username: &str, password: &str) {
    // create the user -> contains secret content
    let new_plain_user = User::generate(username, password);

    // encrypt
    let serialized_ciphered64_user = serde_json::to_string(&new_plain_user.encrypt()).unwrap();

    let client = Client::new();

    match client
        .get(format!("{}/get_sign_up", URL.to_string()))
        .json(&serialized_ciphered64_user)
        .send()
        .await
    {
        Ok(res) => match res.status() {
            // TODO must handle jwt
            StatusCode::CREATED => println!("User successfully created"),
            _ => println!(
                "Error : {}",
                match res.text().await {
                    Ok(t) => t,
                    Err(e) => e.to_string(),
                }
            ),
        },
        Err(e) => println!("Error : {}", e.to_string()),
    }
}

pub fn create_file(path: &str, content: &str, key: Vec<u8>) {}

pub fn create_dir(path: &str) {}
