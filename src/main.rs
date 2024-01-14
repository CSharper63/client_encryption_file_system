use std::borrow::BorrowMut;
use std::ops::DerefMut;
use std::ops::Index;
use std::ops::IndexMut;
use std::vec;

use crate::model::{DirEntity, User};
use cliclack::input;
use cliclack::log;
use cliclack::password;
use cliclack::select;
use cliclack::spinner;
use cliclack::{intro, outro};
use model::FileEntity;
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
    let mut current_path: &str;
    let mut my_user: Option<User> = None;
    let mut root_tree: Option<RootTree> = None;

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
        _ => log::error("Hmmm you are not supposed to be there").unwrap(),
    }

    // now you get connected to the service so get your bucket tree
    if is_connected {
        // fetch the root tree
        root_tree = endpoints::get_my_tree(jwt.unwrap().as_str()).await;

        log::info(format!("Your bucket tree has been fetched successfully")).unwrap();
    }

    log::info(format!(
        "Welcome Mr. {}",
        my_user.as_ref().unwrap().username
    ))
    .unwrap();

    // make a loop to show the tree
    let mut current_path: String = "/".to_string(); // current path when navigate over the tree
    let mut root = root_tree.as_mut().unwrap(); // the current user tree
                                                /* let mut bind_dirs = root.dirs.as_mut().unwrap();
                                                   let mut parent_dirs: Vec<&mut DirEntity> = bind_dirs.iter_mut().collect(); // pseudo linked list
                                                */
    let mut parent_dirs: Vec<&mut DirEntity> = Vec::default();

    // start to iter over the tree
    //let mut selected_dir: &DirEntity; // current selected dir

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

                let new_dir = DirEntity::create(dir_name.as_str(), &current_path);

                let symm_key = if let Some(dir) = parent_dirs.last_mut() {
                    dir.key.asset.clone().unwrap()
                } else {
                    my_user.as_ref().unwrap().symmetric_key.clone()
                };

                if parent_dirs.len() == 0 {
                    // in "/"
                    root.dirs.as_mut().unwrap().push(new_dir);

                    println!("There is no dir so i went there");
                } else {
                    let encr_dir = new_dir.encrypt(symm_key);

                    parent_dirs
                        .last_mut()
                        .unwrap()
                        .sub_dirs
                        .as_mut()
                        .unwrap()
                        .push(encr_dir);
                }

                // todo call api

                println!("root tree: {}", root.to_string());
            }
            "create_file" => {}
            "list_dirs" => {
                // fills the items to select with the sub dirs of the current dir
            }
            _ => log::error("Hmmm you are not supposed to be there").unwrap(),
        }
    }

    // Do stuff
    outro("Okkkkayyyyyy let'sgoooo").unwrap();
}
