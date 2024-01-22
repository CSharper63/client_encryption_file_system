use std::fs::File;
use std::io::Read;
use std::ops::Deref;
use std::path::Path;

use cliclack::input;
use cliclack::intro;
use cliclack::log;
use cliclack::password;
use cliclack::select;
use cliclack::spinner;
use model::Sharing;
use model::User;

use crate::model::FsEntity;
pub mod crypto;
pub mod endpoints;
pub mod model;

#[tokio::main]
async fn main() {
    intro("Welcome to encryption client").unwrap();
    loop {
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
        let mut usr_password: String = password("🔑Provide a password")
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
                    spinner.start("Verifying your account");
                    let (auth_key, _) =
                        User::rebuild_secret(&usr_password.clone(), Some(salt.clone()));

                    jwt = endpoints::sign_in(&username, auth_key.clone()).await;

                    if jwt.as_ref().is_none() {
                        spinner.stop("Invalid credential");
                        usr_password = password("🔑Provide a password")
                            .mask('🙈')
                            .interact()
                            .unwrap();
                    } else {
                        is_connected = true;

                        let fetched_user = endpoints::get_user(jwt.clone().unwrap().as_str()).await;

                        my_user = Some(
                            fetched_user
                                .unwrap()
                                .decrypt(&usr_password, Some(salt.clone())),
                        );

                        spinner.stop("Signed in successfully");
                    }
                }
            }
            // handle new account
            "sign_up" => {
                while jwt.as_ref().is_none() {
                    jwt = endpoints::sign_up(&username, &usr_password).await;
                    if jwt.as_ref().is_none() {
                        username = input("Provide a username")
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
                        let fetched_user = endpoints::get_user(jwt.clone().unwrap().as_str()).await;
                        salt = endpoints::get_salt(&username).await;

                        my_user = Some(fetched_user.unwrap().decrypt(&usr_password, salt.clone()));
                    }
                }
            }
            _ => log::error("Hmmm you are not supposed to be there").unwrap(),
        }

        // now you get connected to the service so get your bucket tree
        if is_connected {
            log::info(format!("Your bucket tree has been fetched successfully")).unwrap();
        }

        log::success(format!(
            "Welcome Mr. {}",
            my_user.as_ref().unwrap().username
        ))
        .unwrap();

        // make a loop to show the tree
        let mut current_path: String = "".to_string(); // current path when navigate over the tree
        let mut encrypted_path: String = "".to_string();

        let mut parent_id: String = "".to_string();

        let mut selected_dir: FsEntity = Default::default();
        let mut items: Vec<(&str, &str, &str)> = Vec::default();

        let mut navigtion_in_owned_elem = false;

        let mut current_is_shared = false;

        // items.push(("back", "Back", ""));

        loop {
            log::info(format!(" -> 📂 You are here: /{}", current_path)).unwrap();

            // if we want o modifiy the tree -> modify dirs_refs_to_process
            items.clear();

            // Ajouter les éléments standards à la liste
            items.push(("create_dir", "Create a dir", ""));
            items.push(("add_file", "Add file", ""));
            items.push(("list_content", "List content", ""));
            items.push(("change_password", "Change password", ""));
            items.push(("sign_out", "Sign out", ""));

            if !parent_id.is_empty() {
                if current_is_shared {
                    items.push(("revoke_share", "Revoke sharing", ""));
                } else {
                    items.push(("share_entity", "Share the element", ""));
                }

                items.push(("back", "Back", ""));
            } else {
                items.push(("list_shared_with_me", "List all shared with me", ""));
            }

            // Afficher la liste pour la sélection par l'utilisateur
            let selected: &str = select("What about now ?").items(&items).interact().unwrap();

            let symm_key = if parent_id.is_empty() {
                my_user.as_ref().unwrap().master_key.clone().asset.unwrap()
            } else {
                selected_dir.key.asset.clone().unwrap()
            };

            // contains all ref to the dir
            match selected {
                "sign_out" => {
                    jwt = Some("".to_string());
                    my_user = None;
                    break;
                }
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

                    let encr_dir = new_dir.clone().encrypt(symm_key);

                    endpoints::create_dir(jwt.as_ref().unwrap(), &encr_dir.clone()).await;
                }
                "add_file" => {
                    let path: String = cliclack::input(
                        "Please enter the absolute path of the file you want to add",
                    )
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

                    /* println!("File name: {}", file_name);
                    println!("Path: {}", encrypted_path); */

                    let mut content = Vec::new();

                    let _ = File::open(path).unwrap().read_to_end(&mut content);

                    //let contents = fs::read(&path).unwrap();

                    let new_file = FsEntity::create(
                        file_name,
                        &encrypted_path,
                        Some(content.clone()),
                        &parent_id.clone(),
                    );

                    let encrypted_file = new_file.clone().encrypt(symm_key.clone());

                    endpoints::add_file(jwt.as_ref().unwrap(), &encrypted_file)
                        .await
                        .unwrap();
                }
                "list_content" => {
                    navigtion_in_owned_elem = true;
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

                        let icon = if dir.clone().entity_type == "dir" {
                            String::from("📂")
                        } else {
                            String::from("💾") // not really a file but fancy
                        };
                        current_is_shared = my_user
                            .as_ref()
                            .unwrap()
                            .is_entity_shared(dir.uid.clone().unwrap().as_str());
                        let shared_status = if current_is_shared { "Shared" } else { "" };

                        items.push((
                            dir.uid.clone().unwrap(),
                            format!("{} {}", icon, name),
                            shared_status,
                        ));
                    }

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
                "change_password" => {
                    let old_1 = password("🔑Provide your current password")
                        .mask('🙈')
                        .interact()
                        .unwrap();

                    let new_1 = password("🔑Provide a new password")
                        .mask('🙈')
                        .interact()
                        .unwrap();

                    // !! must be decrypted before
                    let updated = my_user
                        .as_ref()
                        .unwrap()
                        .update_password(&old_1, new_1.as_str());

                    if updated.clone().is_none() {
                        log::error(format!("Invalid password, please re-sign in")).unwrap();
                    } else {
                        let new_encrypted_user = updated.unwrap().encrypt();

                        endpoints::update_password(
                            &jwt.as_ref().clone().unwrap(),
                            &new_encrypted_user,
                        )
                        .await;

                        log::success(format!("Password changed successfully")).unwrap();
                    }

                    break;
                }

                // about share ->
                // if its a dir, we must add the whole tree children to authorized list access to the person I share with.
                // struct will look like -> {"shared_item_uid":"encrypted key"} -> server must verify that is not a root folder,
                // and must delete the parent id before the sending the shared to the user
                "list_shared_with_me" => {
                    if let Some(shared_to_me) = my_user.as_ref().unwrap().shared_to_me.as_ref() {
                        if shared_to_me.is_empty() {
                            log::info("No items have been shared with you").unwrap();
                        } else {
                            log::info("Items shared with you:").unwrap();

                            /*  loop { */
                            let mut parent_id = "".to_string();

                            let mut selected_shared: Option<Sharing> = None;

                            /* if selected_shared.is_some() {
                                fetched_dirs = endpoints::get_shared_children(
                                    &jwt.as_ref().clone().unwrap(),
                                    &selected_shared.unwrap(),
                                    child_id.clone().as_str(),
                                )
                                .await;
                            } */

                            loop {
                                let mut items: Vec<(String, String, &str)> = Vec::default(); // will contains the item to select
                                let mut decrypted_dirs: Vec<FsEntity> = Vec::default(); // will contains the decrypted dirs
                                                                                        // it means we are in the root, so must list all shared to dig in
                                if selected_shared.is_none() {
                                    for sharing in shared_to_me {
                                        let encrypted_dir = endpoints::get_shared_entity(
                                            jwt.as_ref().unwrap(),
                                            sharing,
                                        )
                                        .await;
                                        let decrypted_dir = encrypted_dir
                                            .unwrap()
                                            .decrypt_from_dir_key(sharing.clone().key.unwrap());

                                        let name = decrypted_dir.clone().show_name();

                                        let icon = if decrypted_dir.clone().entity_type == "dir" {
                                            String::from("📂")
                                        } else {
                                            String::from("💾") // not really a file but fancy
                                        };

                                        items.push((
                                            decrypted_dir.uid.clone().unwrap(),
                                            format!("{} {}", icon, name),
                                            "",
                                        ));

                                        decrypted_dirs.push(decrypted_dir);
                                    }
                                    // else we are in the share
                                } else {
                                    // must get the children from the selected sharing
                                    let fetched_dirs = endpoints::get_shared_children(
                                        &jwt.as_ref().clone().unwrap(),
                                        selected_shared.as_ref().unwrap(),
                                        parent_id.as_str(),
                                    )
                                    .await;

                                    println!(
                                        "GET INTO {}{}",
                                        parent_id.as_str(),
                                        fetched_dirs.clone().unwrap().len()
                                    );

                                    for dir in fetched_dirs.clone().unwrap().iter_mut() {
                                        let decrypted_dir = if parent_id.is_empty() {
                                            // if parent_id is empty it means are in the top of the share tree
                                            dir.clone().decrypt(
                                                selected_shared.clone().unwrap().key.unwrap(),
                                            )
                                        } else {
                                            // else decrypt with the parent key
                                            dir.clone()
                                                .decrypt(selected_dir.key.clone().asset.unwrap())
                                        };

                                        decrypted_dirs.push(decrypted_dir.clone());

                                        let name = decrypted_dir.clone().show_name();

                                        let icon = if dir.clone().entity_type == "dir" {
                                            String::from("📂")
                                        } else {
                                            String::from("💾") // not really a file but fancy
                                        };

                                        items.push((
                                            dir.uid.clone().unwrap(),
                                            format!("{} {}", icon, name),
                                            "",
                                        ));
                                    }
                                }

                                // the selected folder will be now the current parent
                                parent_id = cliclack::select("Pick a folder")
                                    .items(items.as_ref())
                                    .interact()
                                    .unwrap();

                                // contains the selected shared -> so we will dig into is tree
                                if selected_shared.is_none() {
                                    // we must keep the link to the parent shared
                                    selected_shared = Some(
                                        shared_to_me
                                            .iter()
                                            .find(|d| d.entity_uid.clone() == parent_id)
                                            .unwrap()
                                            .clone(),
                                    );
                                }

                                // the current dir matching with the sharing
                                selected_dir = decrypted_dirs
                                    .iter()
                                    .find(|d| d.uid.clone().unwrap() == parent_id)
                                    .unwrap()
                                    .clone();
                                current_path =
                                    add_to_path(&current_path, &selected_dir.show_name());
                                decrypted_dirs.clear();
                            }

                            /*     selected_dir = current_path =
                                                           add_to_path(&current_path, &selected_dir.clone().show_name());
                                                       encrypted_path = add_to_path(
                                                           &encrypted_path,
                                                           &&encry_selected_dir.unwrap().encrypted_name(),
                                                       );
                            */
                            /*  } */
                        }
                    } else {
                        log::info("No items have been shared with you").unwrap();
                    }
                }

                "share_entity" => {
                    let username: String = cliclack::input(
                        "Please enter the username you want to share the element with",
                    )
                    .placeholder("john_doe_76")
                    .validate(|input: &String| {
                        if input.is_empty() {
                            Err("Please enter a username.")
                        } else {
                            Ok(())
                        }
                    })
                    .interact()
                    .unwrap();

                    // get the public key of the user I want to share my dir with
                    let pb_mat =
                        endpoints::get_public_key_with_uid(&jwt.as_ref().unwrap(), &username).await;

                    // encrypt the dir key with the user public key
                    match crypto::encrypt_asymm(
                        pb_mat.clone().unwrap().public_key.unwrap(),
                        selected_dir.key.asset.clone().unwrap(),
                    ) {
                        Ok(encrypted_key) => {
                            let element_expected_2_be_shared = Sharing {
                                entity_uid: selected_dir.clone().uid.unwrap(),
                                key: Some(encrypted_key),
                                owner_id: my_user.as_ref().unwrap().uid.clone().unwrap(),
                                user_id: pb_mat.clone().unwrap().owner_id.unwrap(),
                            };

                            endpoints::share_entity(
                                &jwt.as_ref().clone().unwrap(),
                                &element_expected_2_be_shared,
                            )
                            .await;

                            my_user
                                .as_mut()
                                .unwrap()
                                .share(&element_expected_2_be_shared);
                            current_is_shared = true;
                        }
                        Err(e) => {
                            log::error(format!("Encryption error: {}", e));
                        }
                    }
                }
                "revoke_share" => {
                    let share_2_revoke = my_user
                        .as_ref()
                        .unwrap()
                        .find_sharing_by_entity_id(selected_dir.clone().uid.unwrap().as_str());

                    if share_2_revoke.is_some() {
                        let ok = endpoints::revoke_share(
                            jwt.as_ref().unwrap(),
                            share_2_revoke.as_ref().unwrap(),
                        )
                        .await;

                        my_user
                            .as_mut()
                            .unwrap()
                            .revoke_share(selected_dir.clone().uid.unwrap().as_str());
                        current_is_shared = false;

                        log::success("The share of this item has been revoked successfully");
                    } else {
                        log::warning("This item is not shared yet");
                    }
                }
                "back" => {
                    current_path = pop_from_path(current_path.as_str()).unwrap_or("".to_string());
                    encrypted_path =
                        pop_from_path(encrypted_path.as_str()).unwrap_or("".to_string());

                    parent_id = selected_dir.clone().parent_id.unwrap_or("".to_string());
                }
                _ => log::error("Hmmm you are not supposed to be there").unwrap(),
            }
        }

        // Do stuff
        log::info("Bye bye");
    }
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
