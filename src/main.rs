use std::fs;
use std::path::Path;

use crate::model::{FsEntity, User};
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

    let mut parent_id: String = "".to_string();

    let mut selected_dir: FsEntity = Default::default();
    loop {
        log::info(format!("You are here: /{}", current_path)).unwrap();

        // if we want o modifiy the tree -> modify dirs_refs_to_process

        let selected: &str = select("What about now ?")
            .item("create_dir", "Create a dir", "")
            .item("add_file", "Create a file", "")
            .item("list_dirs", "List all dirs", "")
            .item("list_files", "List all files", "")
            .interact()
            .unwrap();

        // contains all ref to the dir
        match selected {
            "create_dir" => {
                // ask user for a dir name
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

                // generate dir -> content:None
                let new_dir =
                    FsEntity::create(dir_name.as_str(), &encrypted_path, None, &parent_id); // so it s a file

                // compute which key will encrypt the dir -> if at root -> user mk else parent dir key
                let symm_key = if parent_id.is_empty() {
                    my_user.as_ref().unwrap().master_key.clone().asset.unwrap()
                } else {
                    selected_dir.key.asset.clone().unwrap()
                };

                let encr_dir = new_dir.clone().encrypt(symm_key);

                endpoints::create_dir(jwt.as_ref().unwrap(), &encr_dir.clone()).await;
            }
            "add_file" => {
                let path: String =
                    cliclack::input("Please enter the absolute path of the file you want to add")
                        .placeholder("C:\\path\\to\\file")
                        .validate(|input: &String| {
                            if input.is_empty() {
                                Err("Please enter a path.")
                            } else {
                                Ok(())
                            }
                        })
                        .interact()
                        .unwrap();
                let path = Path::new(&path);

                let file_name = path.file_name().unwrap().to_str().unwrap();

                println!("File name: {}", file_name);

                let contents = fs::read(&path).unwrap();

                let new_file = FsEntity::create(
                    file_name,
                    &encrypted_path,
                    Some(contents.clone()),
                    &parent_id.clone(),
                );
                let file_key = new_file.clone().key.asset.unwrap();
                let encrypted_file = new_file.encrypt(file_key);

                endpoints::add_file(&jwt.as_ref().unwrap(), &encrypted_file);
                println!("File content: {:?}", contents);
            }
            "list_dirs" => {
                //list all folder by names and uid, then get into, and fetch the child from endpoint
                let fetched_dirs: Option<Vec<FsEntity>>;

                // means we are in root so list all

                fetched_dirs =
                    endpoints::get_children(&jwt.as_ref().clone().unwrap(), parent_id.as_str())
                        .await;
                let mut items: Vec<(String, String, &str)> = Vec::default(); // will contains the item to select
                let mut decrypted_dirs: Vec<FsEntity> = Vec::default(); // will contains the decrypted dirs

                for dir in fetched_dirs.clone().unwrap().iter_mut() {
                    let decrypted_dir = if parent_id.is_empty() {
                        // if parent_id is empty it means we must decrypt with the user master key
                        dir.clone().decrypt(
                            my_user
                                .as_ref()
                                .unwrap()
                                .master_key
                                .clone()
                                .asset
                                .clone()
                                .unwrap(),
                        )
                    } else {
                        // else decrypt with the parent key
                        dir.clone().decrypt(selected_dir.key.clone().asset.unwrap())
                        // TODO decrypt with own key if decrypt files
                    };

                    decrypted_dirs.push(decrypted_dir.clone());

                    let name = decrypted_dir.clone().show_name();

                    items.push((dir.uid.clone().unwrap(), format!("📂 {}", name), ""));
                }
                println!("I am done at this point");

                parent_id = cliclack::select("Pick a folder")
                    .items(items.as_ref())
                    .interact()
                    .unwrap();

                selected_dir = decrypted_dirs
                    .iter()
                    .find(|d| d.uid.clone().unwrap() == parent_id)
                    .unwrap()
                    .clone();

                let encry_selected_dir = fetched_dirs
                    .as_ref()
                    .unwrap()
                    .iter()
                    .find(|d| d.uid.clone().unwrap() == parent_id);

                current_path = add_to_path(&current_path, &selected_dir.clone().show_name());
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
    if current_path == "" {
        format!("{}", element)
    } else {
        format!("{}/{}", current_path, element)
    }
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
