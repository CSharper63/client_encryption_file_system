use crate::model::{DirEntity, User};
use cliclack::input;
use cliclack::log;
use cliclack::password;
use cliclack::select;
use cliclack::spinner;
use cliclack::{intro, outro};
use model::RootTree;

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

    // select if you already got an account or not
    let selected: &str = select("Do you have an account ?")
        .item("sign_in", "Yes, let's connect", "")
        .item("sign_up", "Nope, let me discover it", "looser")
        .interact()
        .unwrap();

    // provide a username
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

    // provide a password
    let mut usr_password: String = password("Provide a password")
        .mask('🙈')
        .interact()
        .unwrap();

    // check if you need to sign in or sign up
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
            while jwt.as_ref().is_none() {
                let (auth_key, _) = User::rebuild_secret(&usr_password.clone(), Some(salt.clone()));

                jwt = endpoints::sign_in(&username, auth_key.clone()).await;

                if jwt.as_ref().is_none() {
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
            while jwt.as_ref().is_none() {
                jwt = endpoints::sign_up(&username, &usr_password).await;
                if jwt.as_ref().is_none() {
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

                    my_user = Some(my_user.unwrap().decrypt(&usr_password, salt.clone()));
                }
            }
        }
        _ => log::error("Hmmm you are not supposed to be there").unwrap(),
    }

    // now you get connected to the service so get your bucket tree
    if is_connected {
        log::info(format!("Your bucket tree has been fetched successfully")).unwrap();
    }

    log::info(format!(
        "Welcome Mr. {}",
        my_user.as_ref().unwrap().username
    ))
    .unwrap();

    // make a loop to show the tree
    let mut current_path: String = "".to_string(); // current path when navigate over the tree
    let mut encrypted_path: String = "".to_string();

    let mut parent_dirs: Vec<&mut DirEntity> = Vec::default();

    let mut parent_id: String = "".to_string();
    loop {
        log::info(format!("You are here: {}", current_path)).unwrap();

        // if we want o modifiy the tree -> modify dirs_refs_to_process

        let selected: &str = select("What about now ?")
            .item("create_dir", "Create a dir", "")
            .item("create_file", "Create a file", "")
            .item("list_dirs", "List all dirs", "")
            .item("list_files", "List all files", "")
            .interact()
            .unwrap();

        // contains all ref to the dir
        match selected {
            "create_dir" => {
                let dir_name: String = input("Provide me a directory name")
                    .placeholder("Not sure")
                    .validate(|input: &String| {
                        if input.is_empty() {
                            Err("Name is required!")
                        } else {
                            Ok(())
                        }
                    })
                    .interact()
                    .unwrap();

                let new_dir =
                    DirEntity::create(dir_name.as_str(), &encrypted_path, "dir", &parent_id);

                let symm_key = if let Some(dir) = parent_dirs.last_mut() {
                    //println!("Dir key will be used");
                    dir.key.asset.clone().unwrap()
                } else {
                    println!("User key will be used");

                    my_user.as_ref().unwrap().master_key.clone().asset.unwrap()
                };

                let encr_dir = new_dir.clone().encrypt(symm_key);

                endpoints::create_dir(jwt.as_ref().unwrap(), &encr_dir.clone()).await;
            }
            "create_file" => {}
            "list_dirs" => {
                //list all folder by names and uid, then get into, and fetch the child from endpoint
                let fetched_dirs: Option<Vec<DirEntity>>;

                // means we are in root so list all

                fetched_dirs =
                    endpoints::get_children(&jwt.as_ref().clone().unwrap(), parent_id.as_str())
                        .await;
                let mut items: Vec<(String, String, &str)> = Vec::default(); // will contains the item to select
                let mut decrypted_dirs: Vec<DirEntity> = Vec::default(); // will contains the decrypted dirs

                for dir in fetched_dirs.clone().unwrap().iter_mut() {
                    let decrypted_dir = dir.clone().decrypt(
                        my_user
                            .as_ref()
                            .unwrap()
                            .master_key
                            .clone()
                            .asset
                            .clone()
                            .unwrap(),
                    );

                    decrypted_dirs.push(decrypted_dir.clone());

                    let name = decrypted_dir.clone().show_name();

                    items.push((dir.uid.clone().unwrap(), format!("📂 {}", name), ""));
                }
                println!("I am done at this point");

                parent_id = cliclack::select("Pick a folder")
                    .items(items.as_ref())
                    .interact()
                    .unwrap();

                let selected_dir = decrypted_dirs
                    .iter()
                    .find(|d| d.uid.clone().unwrap() == parent_id);

                let encry_selected_dir = fetched_dirs
                    .as_ref()
                    .unwrap()
                    .iter()
                    .find(|d| d.uid.clone().unwrap() == parent_id);

                current_path = add_to_path(&current_path, &selected_dir.unwrap().show_name());
                encrypted_path = add_to_path(
                    &encrypted_path,
                    &&encry_selected_dir.unwrap().encrypted_name(),
                );
            }
            _ => log::error("Hmmm you are not supposed to be there").unwrap(),
        }
    }

    // Do stuff
    outro("Okkkkayyyyyy let'sgoooo").unwrap();
}

fn add_to_path(current_path: &str, element: &str) -> String {
    format!("{}/{}", current_path, element)
}

fn pop_from_path(current_path: &str) -> Option<String> {
    let mut components: Vec<&str> = current_path.split('/').collect();
    components.pop();
    if !components.is_empty() {
        Some(components.join("/"))
    } else {
        None
    }
}
