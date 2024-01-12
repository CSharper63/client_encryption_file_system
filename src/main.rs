use crate::model::{DirEntity, User};
use cliclack::input;
use cliclack::log;
use cliclack::password;
use cliclack::select;
use cliclack::spinner;
use cliclack::{intro, outro};

pub struct Index<'a> {
    pub current_dir: &'a mut DirEntity,
    pub parent_dirs: Vec<&'a DirEntity>,
}

pub mod crypto;
pub mod endpoints;
pub mod model;
#[tokio::main]
async fn main() {
    intro("Welcome to encryption client").unwrap();

    let mut jwt: Option<String> = None;
    let mut salt: Option<Vec<u8>> = None;
    let mut spinner = spinner();
    let mut is_connected: bool = false;

    let mut my_user: Option<User> = None;

    let selected: &str = select("Do you have an account ?")
        .item("sign_in", "Yes, let's connect", "")
        .item("sign_up", "Nope, let me discover it", "looser")
        .interact()
        .unwrap();

    let mut username: String = input("Provide me a username")
        .placeholder("Not sure")
        .validate(|input: &String| {
            if input.is_empty() {
                Err("Value is required!")
            } else {
                Ok(())
            }
        })
        .interact()
        .unwrap();

    let mut usr_password: String = password("Provide a password")
        .mask('🙈')
        .interact()
        .unwrap();

    match selected {
        // this case handle existing account
        "sign_in" => {
            // getting the salt// Sign in

            while salt.is_none() {
                spinner.start("Getting the salt...");
                salt = endpoints::get_salt(&username).await;

                if salt.is_none() {
                    spinner.stop("Unable to get the salt, please retry");
                    username = input("Provide me a username")
                        .placeholder("Not sure")
                        .validate(|input: &String| {
                            if input.is_empty() {
                                Err("Value is required!")
                            } else {
                                Ok(())
                            }
                        })
                        .interact()
                        .unwrap();
                } else {
                    spinner.stop("Salt successfully fetched");
                }
            }
            let salt = salt.unwrap(); // safe to unwrap here because salt is not None

            // Rebuild the secret
            while jwt.is_none() {
                let (auth_key, _) = User::rebuild_secret(&usr_password.clone(), Some(salt.clone()));

                jwt = endpoints::sign_in(&username, auth_key.clone()).await;

                if jwt.is_none() {
                    spinner.stop("Invalid credential");
                    usr_password = password("Provide a password")
                        .mask('🙈')
                        .interact()
                        .unwrap();
                } else {
                    is_connected = true;

                    my_user = endpoints::get_user(jwt.clone().unwrap().as_str()).await;

                    my_user = Some(my_user.unwrap().decrypt(&usr_password, Some(salt.clone())));

                    spinner.stop("Signed in successfully");
                }
            }
        }
        // handle new account
        "sign_up" => {
            while jwt.is_none() {
                jwt = endpoints::sign_up(&username, &usr_password).await;
                if jwt.is_none() {
                    username = input("Provide me a username")
                        .placeholder("Not sure")
                        .validate(|input: &String| {
                            if input.is_empty() {
                                Err("Value is required!")
                            } else {
                                Ok(())
                            }
                        })
                        .interact()
                        .unwrap();
                    usr_password = password("Provide a password")
                        .mask('🙈')
                        .interact()
                        .unwrap();
                } else {
                    is_connected = true;
                    spinner.stop("Account successfully created !");
                    my_user = endpoints::get_user(jwt.clone().unwrap().as_str()).await;
                    salt = endpoints::get_salt(&username).await;

                    my_user = Some(my_user.unwrap().decrypt(&usr_password, salt));
                }
            }
        }
        _ => println!("something else!"),
    }

    log::info(format!("Welcome Mr. {}", my_user.unwrap().username)).unwrap();

    let selected: &str = select("What about now ?")
        .item("create_dir", "Create a subdir", "")
        .item("create_file", "Create a file", "")
        .item("create_file", "Get into a dir", "")
        .interact()
        .unwrap();

    // Do stuff
    outro("Okkkkayyyyyy let'sgoooo").unwrap();
}
