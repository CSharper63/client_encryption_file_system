use std::ops::Add;
use std::ops::Deref;
use std::ops::DerefMut;

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
        // fetch the root tree
        root_tree = endpoints::get_my_tree(jwt.as_ref().unwrap().as_str()).await;

        log::info(format!("Your bucket tree has been fetched successfully")).unwrap();
    }

    log::info(format!(
        "Welcome Mr. {}",
        my_user.as_ref().unwrap().username
    ))
    .unwrap();

    // make a loop to show the tree
    let mut current_path: String = "/".to_string(); // current path when navigate over the tree
    let root = root_tree.as_mut().unwrap(); // the current user tree
                                            /* let mut bind_dirs = root.dirs.as_mut().unwrap();
                                               let mut parent_dirs: Vec<&mut DirEntity> = bind_dirs.iter_mut().collect(); // pseudo linked list
                                            */
    let mut parent_dirs: Vec<&mut DirEntity> = Vec::default();

    // start to iter over the tree
    //let mut selected_dir: &DirEntity; // current selected dir

    let mut ref_dir_index: usize = 0;
    let mut selected_dir: &mut DirEntity;

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
                    //println!("Dir key will be used");
                    dir.key.asset.clone().unwrap()
                } else {
                    println!("User key will be used");

                    my_user.as_ref().unwrap().master_key.clone().asset.unwrap()
                };

                //println!("Used key: {}", bs58::encode(symm_key.clone()).into_string());

                let encr_dir = new_dir.clone().encrypt(symm_key);

                if parent_dirs.len() == 0 {
                    // in "/"
                    root.dirs.as_mut().unwrap().push(encr_dir.clone());

                    println!("There is no dir so i went there");
                } else {
                    parent_dirs
                        .last_mut()
                        .unwrap()
                        .sub_dirs
                        .as_mut()
                        .unwrap()
                        .push(encr_dir.clone());
                }

                // todo call api

                endpoints::create_dir(jwt.as_ref().unwrap(), &encr_dir.clone()).await;
                endpoints::update_tree(jwt.as_ref().unwrap(), &root.clone()).await;

                //println!("root tree: {}", root.to_string());
            }
            "create_file" => {}
            "list_dirs" => {
                // fills the items to select with the sub dirs of the current dir

                if parent_dirs.len() == 0 {
                    let mut items: Vec<(usize, String, &str)> = Vec::default(); // will contains the item to select

                    // must list root
                    let mut decrypted_dirs: Vec<DirEntity> = Vec::default(); // will contains the decrypted dirs
                    let all_dirs: &mut Vec<DirEntity> = root.dirs.as_mut().unwrap(); // or as_ref
                                                                                     /*                     println!("Dir ok");
                                                                                      */

                    for dir in all_dirs.iter_mut() {
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
                        /*                         println!("Decryption ok");
                         */
                        let name = decrypted_dir.clone().show_name(); // add the name of the current ref dir
                                                                      /* println!("Name ok: {}", name.clone()); */

                        items.push((ref_dir_index, format!("📂 {}", name), ""));
                        /*                         println!("item ok");
                         */
                        ref_dir_index = ref_dir_index + 1;
                        // update the index
                        // add the index with the folder name with the folder name
                    }
                    println!("I am done at this point");
                    let selected_index: usize = cliclack::select("Pick a folder")
                        .items(items.as_ref())
                        .interact()
                        .unwrap();
                    ref_dir_index = selected_index;

                    // add the selected folder to parent_dirs to keep tracking if need 2 get back
                    /*                     parent_dirs.push(all_dirs.get_mut(ref_dir_index).unwrap()); // !! <-------------------------------------------
                     */
                    // at this point they must be decrypted
                    // iteratate over the dir to select it
                } else { // must list parent.last
                }
            }
            _ => log::error("Hmmm you are not supposed to be there").unwrap(),
        }
    }

    // Do stuff
    outro("Okkkkayyyyyy let'sgoooo").unwrap();
}
