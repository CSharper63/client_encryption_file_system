pub mod crypto;
pub mod endpoints;
pub mod model;
#[tokio::main]
async fn main() {
    println!("Hello, world!");

    let password = "password";
    let username = "john";

    // call the api to register the user
    let (jwt, clear_user) = endpoints::sign_up(username, password).await;

    println!(
        "{}/{}",
        jwt.unwrap().clone(),
        bs58::encode(clear_user.clone().unwrap().master_key.asset.unwrap()).into_string()
    );

    let enc_user = clear_user.clone().unwrap().encrypt();
}
