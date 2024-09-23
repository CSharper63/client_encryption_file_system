use cliclack::input;
use cliclack::intro;
use cliclack::log;
use cliclack::password;
use cliclack::select;
use cliclack::spinner;
use models::fs_entity::FsEntity;
use models::sharing::Sharing;
use models::user::User;

use std::env;
use std::fs;
use std::fs::File;
use std::io::Read;
use std::path::Path;
pub mod crypto;
pub mod endpoints;
pub mod models;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    intro("Welcome to encryption client")?;
    loop {
        // select if you already got an account or not

        let selected: &str = select("Do you have an account ?")
            .item("sign_in", "\x1b[1mYES\x1b[0m, let's connect", "")
            .item(
                "sign_up",
                "\x1b[1mNOPE\x1b[0m, let me discover it",
                "looser",
            )
            .interact()?;

        // check if you need to sign in or sign up
        match selected {
            // this case handle existing account
            "sign_in" => {
                if let Ok(Some((jwt, mut my_user))) = sign_in().await {
                    navigate_over(&mut my_user, jwt.as_str()).await?;
                }
            }
            // handle new account
            "sign_up" => {
                if let Ok(Some((jwt, mut my_user))) = sign_up().await {
                    navigate_over(&mut my_user, jwt.as_str()).await?;
                }
            }
            _ => log::error("Hmmm you are not supposed to be there")?,
        }

        // Do stuff
        log::info("Bye bye")?;
    }
}

// !! can be factorised
async fn navigate_over(my_user: &mut User, jwt: &str) -> Result<(), Box<dyn std::error::Error>> {
    log::success(format!("Welcome Mr. {}", my_user.clone().username))?;

    let (mut current_path, mut encrypted_path, mut parent_id) =
        ("".to_string(), "".to_string(), "".to_string()); // current path when navigate over the tree

    let mut selected_dir: Option<FsEntity> = None;
    let mut items: Vec<(&str, &str, &str)> = Vec::default();

    let mut current_is_shared = false;
    let mut chain_of_dirs: Vec<FsEntity> = Vec::default();

    Ok(loop {
        log::info(format!(" -> 📁 You are here: /{}", current_path.clone()))?;

        // if we want o modifiy the tree -> modify dirs_refs_to_process
        items.clear();

        items.push(("create_dir", "🆕 Create a dir", ""));
        items.push(("add_file", "🆕 Add file", ""));
        items.push(("list_content", "📂 List content", ""));
        items.push(("change_password", "🔐 Change password", ""));
        items.push(("sign_out", "🚪 Sign out", ""));

        if !parent_id.is_empty() {
            if current_is_shared {
                items.push(("revoke_share", "🔗 Revoke sharing", ""));
            } else {
                items.push(("share_entity", "🔗 Share the element", ""));
            }

            items.push(("back", "Back", ""));
        } else {
            items.push(("list_shared_with_me", "🔗 List all shared with me", ""));
        }

        // Afficher la liste pour la sélection par l'utilisateur
        let selected: &str = select("What about now ?").items(&items).interact()?;

        let symm_key = if parent_id.is_empty() {
            my_user.clone().master_key.clone().asset.unwrap()
        } else {
            selected_dir.as_ref().unwrap().key.asset.clone().unwrap()
        };

        // contains all ref to the dir
        match selected {
            "sign_out" => {
                my_user.erase_secret()?;
                break;
            }
            "create_dir" => {
                // ask user for a dir name
                let dir_name = get_valid_input("Provide me a directory name", "Name is required!");

                // generate dir -> content:None
                let mut new_dir =
                    FsEntity::create(dir_name.as_str(), &encrypted_path, None, &parent_id)?; // so it s a file

                // compute which key will encrypt the dir -> if at root -> user mk else parent dir key

                new_dir.encrypt(symm_key)?;

                endpoints::create_dir(jwt, &new_dir).await;
            }
            "add_file" => {
                let path = get_valid_input(
                    "Please enter the absolute path of the file you want to add",
                    "Please enter a path.",
                );

                let path = Path::new(&path);

                let file_name = path.file_name().unwrap().to_str().unwrap();

                let mut content = Vec::new();

                let _ = File::open(path).unwrap().read_to_end(&mut content);

                //let contents = fs::read(&path).unwrap();

                let mut new_file = FsEntity::create(
                    file_name,
                    &encrypted_path,
                    Some(content.clone()),
                    &parent_id.clone(),
                )?;

                new_file.encrypt(symm_key.clone())?;

                endpoints::add_file(jwt, &new_file).await;
            }
            "list_content" => {
                // Fetch directories or files from the endpoint
                let fetched_dirs = endpoints::get_children(&jwt, parent_id.as_str()).await;
                let mut dirs = fetched_dirs.unwrap();

                if dirs.is_empty() {
                    log::info("There is no content in this directory").unwrap();
                    continue;
                }

                let mut items: Vec<(String, String, &str)> = Vec::new(); // Items to select
                let mut decrypted_dirs: Vec<FsEntity> = Vec::new(); // Decrypted directories

                // Iterate and decrypt directories
                for dir in dirs.iter_mut() {
                    let key_2_use = if parent_id.is_empty() {
                        my_user.master_key.asset.clone()
                    } else {
                        selected_dir.as_ref().unwrap().key.asset.clone()
                    };

                    dir.decrypt(key_2_use.unwrap())?;

                    let name = dir.show_name();

                    decrypted_dirs.push(dir.clone());

                    let icon = if dir.entity_type == "dir" {
                        "📂"
                    } else {
                        "💾"
                    };

                    let shared_status =
                        if my_user.is_entity_shared(dir.uid.clone().unwrap().as_str()) {
                            "Shared"
                        } else {
                            ""
                        };

                    items.push((
                        dir.uid.clone().unwrap(),
                        format!("{} {}", icon, name),
                        shared_status,
                    ));
                }

                if items.is_empty() {
                    break;
                    //continue;
                }

                // User selection interaction
                let selected_id = cliclack::select("Pick an item").items(&items).interact()?;

                let selected_element = Some(
                    decrypted_dirs
                        .iter()
                        .find(|d| d.uid.clone().unwrap() == selected_id)
                        .unwrap()
                        .clone(),
                );

                // Handle directory or file
                if selected_element.as_ref().unwrap().entity_type == "dir" {
                    selected_dir = selected_element;
                    parent_id = selected_id;
                    chain_of_dirs.push(selected_dir.as_ref().unwrap().clone());
                    let encry_selected_dir =
                        dirs.iter().find(|d| d.uid.clone().unwrap() == parent_id);

                    current_path =
                        add_to_path(&current_path, &selected_dir.as_ref().unwrap().show_name());
                    encrypted_path = add_to_path(
                        &encrypted_path,
                        &encry_selected_dir.unwrap().encrypted_name(),
                    );
                } else {
                    // File handling
                    let selected_file = selected_element;

                    let selected: &str = select("What do you want to do with this file?")
                        .item("share_file", "Share this file", "")
                        .item("download", "Download it", "")
                        .item("back", "Back", "")
                        .interact()?;
                    match selected {
                        "share_file" => {
                            let username = get_valid_input(
                                "Please enter the username you want to share the element with",
                                "Please enter a username.",
                            );

                            // get the public key of the user I want to share my dir with
                            let pb_mat = endpoints::get_public_key_with_uid(&jwt, &username).await;

                            // encrypt the dir key with the user public key
                            let Ok(encrypted_key) = crypto::encrypt_asymm(
                                pb_mat.clone().unwrap().public_key.unwrap(),
                                selected_file.as_ref().unwrap().key.asset.clone().unwrap(),
                            ) else {
                                log::error(format!("Encryption error")).unwrap();
                                break;
                            };

                            let element_expected_2_be_shared = Sharing {
                                entity_uid: selected_file.as_ref().unwrap().clone().uid.unwrap(),
                                key: Some(encrypted_key),
                                owner_id: my_user.clone().uid.clone().unwrap(),
                                user_id: pb_mat.clone().unwrap().owner_id.unwrap(),
                            };

                            endpoints::share_entity(&jwt, &element_expected_2_be_shared).await;

                            my_user.share(&element_expected_2_be_shared);
                            current_is_shared = true;
                        }
                        "download" => {
                            download_decrypted(
                                jwt,
                                &selected_file.as_ref().unwrap(),
                                my_user.clone().uid.unwrap().as_str(),
                                &current_path,
                                FileStatus::Own,
                            )
                            .await;
                        }
                        "back" => continue,
                        _ => {}
                    }
                }
            }
            "change_password" => {
                // todo review, crash after changing
                let old_1 = get_password_input("🔑Provide your current password");

                let new_1 = get_password_input("🔑Provide a new password");

                // !! must be decrypted before
                let former_auth_key = my_user.update_password(&old_1, new_1.as_str())?;

                my_user.encrypt()?;

                endpoints::update_password(&jwt, &my_user, former_auth_key.as_str()).await;
                my_user.erase_secret()?;

                log::success(format!("Password changed successfully"))?;

                break;
            }
            // about share ->
            // if its a dir, we must add the whole tree children to authorized list access to the person I share with.
            // struct will look like -> {"shared_item_uid":"encrypted key"} -> server must verify that is not a root folder,
            // and must delete the parent id before the sending the shared to the user
            "list_shared_with_me" => {
                if let Some(shared_to_me) = my_user.shared_to_me.as_ref() {
                    if shared_to_me.is_empty() {
                        log::info("No items have been shared with you")?;
                    } else {
                        log::info("Items shared with you:")?;

                        let mut parent_id = "".to_string();

                        let mut selected_shared: Option<Sharing> = None;

                        loop {
                            let mut items: Vec<(String, String, &str)> = Vec::default(); // will contains the item to select
                            let mut decrypted_dirs: Vec<FsEntity> = Vec::default(); // will contains the decrypted dirs
                                                                                    // it means we are in the root, so must list all shared to dig in
                            if selected_shared.is_none() {
                                log::warning("No shared selected yet").unwrap();
                                for sharing in shared_to_me {
                                    let Ok(mut encrypted_dir) =
                                        endpoints::get_shared_entity(jwt, sharing).await
                                    else {
                                        log::info("There is no content in this directory")?;
                                        break;
                                    };

                                    log::warning(format!(
                                        "There is {}",
                                        shared_to_me.clone().len()
                                    ))?;

                                    // decrypted from this point
                                    encrypted_dir
                                        .decrypt_from_dir_key(sharing.clone().key.unwrap())?;

                                    let icon = if encrypted_dir.entity_type == "dir" {
                                        String::from("📂")
                                    } else {
                                        String::from("💾") // not really a file but fancy
                                    };

                                    items.push((
                                        encrypted_dir.uid.clone().unwrap(),
                                        format!("{} {}", icon, encrypted_dir.show_name()),
                                        "",
                                    ));

                                    decrypted_dirs.push(encrypted_dir);
                                }
                                if items.len() == 0 {
                                    break;
                                }
                                // else we are in the share
                            } else {
                                // must get the children from the selected sharing
                                let fetched_dirs = endpoints::get_shared_children(
                                    &jwt,
                                    selected_shared.as_ref().unwrap(),
                                    parent_id.as_str(),
                                )
                                .await;

                                if fetched_dirs.is_some() {
                                    for dir in fetched_dirs.clone().unwrap().iter_mut() {
                                        if parent_id.is_empty() {
                                            // if parent_id is empty it means are in the top of the share tree
                                            dir.clone().decrypt(
                                                selected_shared.clone().unwrap().key.unwrap(),
                                            )?
                                        } else {
                                            // else decrypt with the parent key
                                            dir.clone().decrypt(
                                                selected_dir
                                                    .as_ref()
                                                    .unwrap()
                                                    .key
                                                    .clone()
                                                    .asset
                                                    .unwrap(),
                                            )?
                                        };

                                        decrypted_dirs.push(dir.clone());

                                        let name = dir.show_name();

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
                                } else {
                                    log::info("There is no content in this directory")?;
                                }
                                if items.len() == 0 {
                                    break;
                                }
                            }

                            // the selected folder will be now the current parent
                            let selected_id = cliclack::select("Pick a folder")
                                .items(items.as_ref())
                                .interact()
                                .unwrap();
                            log::warning(format!("Dossier selectioné is {}", selected_id))?;

                            // contains the selected shared -> so we will dig into is tree
                            if selected_shared.is_none() {
                                // we must keep the link to the parent shared
                                selected_shared = Some(
                                    shared_to_me
                                        .iter()
                                        .find(|d| d.entity_uid.clone() == selected_id)
                                        .unwrap()
                                        .clone(),
                                );
                            }

                            // the current dir matching with the sharing
                            let selected_element = Some(
                                decrypted_dirs
                                    .iter()
                                    .find(|d| d.uid.clone().unwrap() == selected_id)
                                    .unwrap()
                                    .clone(),
                            );

                            if selected_element.as_ref().unwrap().entity_type == "dir" {
                                selected_dir = selected_element;
                                parent_id = selected_id;
                                chain_of_dirs.push(selected_dir.as_ref().unwrap().clone());

                                current_path = add_to_path(
                                    &current_path,
                                    &selected_dir.as_ref().unwrap().show_name(),
                                );

                                decrypted_dirs.clear();
                            } else {
                                //######################################################## handle case of file:
                                let selected_file = selected_element;

                                let selected: &str =
                                    select("What do you want to do with this file?")
                                        .item("download", "Download it", "")
                                        .item("back", "Back", "")
                                        .interact()?;
                                match selected {
                                    "download" => {
                                        download_decrypted(
                                            jwt,
                                            &selected_file.as_ref().unwrap(),
                                            &selected_shared.as_ref().unwrap().owner_id,
                                            &current_path,
                                            FileStatus::Shared,
                                        )
                                        .await;
                                        break;
                                    }
                                    "back" => continue,
                                    _ => {}
                                }
                            }
                        }
                    }
                } else {
                    log::info("No items have been shared with you")?;
                }
            }
            "share_entity" => {
                let username: String =
                    cliclack::input("Please enter the username you want to share the element with")
                        .placeholder("john_doe_76")
                        .validate(|input: &String| {
                            if input.is_empty() {
                                Err("Please enter a username.")
                            } else {
                                Ok(())
                            }
                        })
                        .interact()?;

                // get the public key of the user I want to share my dir with
                let pb_mat = endpoints::get_public_key_with_uid(&jwt, &username).await;

                // encrypt the dir key with the user public key
                match crypto::encrypt_asymm(
                    pb_mat.clone().unwrap().public_key.unwrap(),
                    selected_dir.as_ref().unwrap().key.asset.clone().unwrap(),
                ) {
                    Ok(encrypted_key) => {
                        let element_expected_2_be_shared = Sharing {
                            entity_uid: selected_dir.as_ref().unwrap().clone().uid.unwrap(),
                            key: Some(encrypted_key),
                            owner_id: my_user.uid.clone().unwrap(),
                            user_id: pb_mat.clone().unwrap().owner_id.unwrap(),
                        };

                        endpoints::share_entity(&jwt, &element_expected_2_be_shared).await;

                        my_user.share(&element_expected_2_be_shared);
                        current_is_shared = true;
                    }
                    Err(e) => {
                        log::error(format!("Encryption error: {}", e))?;
                    }
                }
            }
            "revoke_share" => {
                let Ok(share_2_revoke) = my_user.find_sharing_by_entity_id(
                    selected_dir.as_ref().unwrap().clone().uid.unwrap().as_str(),
                ) else {
                    log::warning("This item is not shared yet")?;
                    break;
                };
                let ok = endpoints::revoke_share(jwt, &share_2_revoke).await;
                if ok.is_some() {
                    my_user
                        .revoke_share(selected_dir.as_ref().unwrap().clone().uid.unwrap().as_str());
                    current_is_shared = false;
                }
            }
            "back" => {
                current_path = pop_from_path(current_path.as_str()).unwrap_or("".to_string());
                encrypted_path = pop_from_path(encrypted_path.as_str()).unwrap_or("".to_string());

                parent_id = selected_dir
                    .as_ref()
                    .unwrap()
                    .clone()
                    .parent_id
                    .unwrap_or("".to_string());
                chain_of_dirs.pop();

                if !parent_id.is_empty() {
                    selected_dir = Some(chain_of_dirs.last().cloned().unwrap());
                }
            }
            _ => log::error("Hmmm you are not supposed to be there")?,
        };
    })
}

fn add_to_path(current_path: &str, element: &str) -> String {
    if current_path.is_empty() {
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

fn get_password_input(prompt: &str) -> String {
    password(prompt).mask('🙈').interact().unwrap()
}

async fn save_file_locally(name: &str, content: Vec<u8>, path: String, status: FileStatus) {
    // get current path
    let current_dir = env::current_dir().unwrap();

    //compute the path
    let target_dir = match status {
        FileStatus::Own => current_dir.join(format!("vault/owned/{}", path)),
        FileStatus::Shared => current_dir.join(format!("vault/shared/{}", path)),
    };

    // create the tree
    if !Path::new(&target_dir).exists() {
        fs::create_dir_all(&target_dir).unwrap();
    }

    // join path
    let file_path = target_dir.join(name);
    let mut spin = spinner();
    spin.start("Saving file in local...");
    match fs::write(file_path.clone(), content) {
        Ok(_) => {
            spin.stop(format!(
                "File successfully saved at: {}",
                file_path.clone().to_string_lossy()
            ));
        }
        Err(_) => {
            spin.stop(format!(
                "Unable to save file: {}",
                file_path.clone().to_string_lossy()
            ));
        }
    };
}

async fn sign_in() -> Result<Option<(String, User)>, Box<dyn std::error::Error>> {
    let mut salt: Option<Vec<u8>> = None;
    let mut jwt: Option<String> = None;
    let mut usr_password = String::from("");
    while salt.is_none() || jwt.is_none() {
        let username = get_valid_input("Provide me a username", "Value is required!");

        salt = endpoints::get_salt(&username).await;

        usr_password = get_password_input("🔑Provide a password");

        let (auth_key, _) = User::rebuild_secret(&usr_password.clone(), salt.clone())?;

        jwt = endpoints::sign_in(&username, auth_key.clone()).await;
    }

    let Some(mut fetched_user) = endpoints::get_user(jwt.clone().unwrap().as_str()).await else {
        return Err("Unable to fetch user".into());
    };

    fetched_user.decrypt(&usr_password, salt.clone())?;

    Ok(Some((jwt.unwrap(), fetched_user)))
}

async fn sign_up() -> Result<Option<(String, User)>, Box<dyn std::error::Error>> {
    let mut jwt = String::from("");
    let mut username = String::from("");
    let mut usr_password = String::from("");

    while jwt.is_empty() {
        username = get_valid_input("Provide a username", "Value is required!");
        usr_password = get_password_input("🔑Provide a password");
        jwt = endpoints::sign_up(&username, &usr_password)
            .await
            .unwrap()
            .unwrap();
    }

    let Some(mut fetched_user) = endpoints::get_user(jwt.clone().as_str()).await else {
        return Err("Cannot get user".into());
    };

    let salt = endpoints::get_salt(&username).await.unwrap();

    fetched_user.decrypt(&usr_password, Some(salt.clone()))?;

    Ok(Some((jwt, fetched_user)))
}

fn get_valid_input(prompt: &str, error_msg: &str) -> String {
    let error_msg = error_msg.to_owned();

    input(prompt)
        .placeholder("Not sure")
        .validate(move |input: &String| {
            if input.is_empty() {
                Err(error_msg.clone())
            } else {
                Ok(())
            }
        })
        .interact()
        .unwrap()
}

enum FileStatus {
    Own,
    Shared,
}
async fn download_decrypted(
    jwt: &str,
    file: &FsEntity,
    owner_id: &str,
    current_path: &str,
    status: FileStatus,
) {
    let content = endpoints::get_file(jwt, file.uid.clone().unwrap().as_str(), owner_id).await;

    let decrypted = crypto::decrypt(
        file.clone().key.asset.unwrap(),
        file.content.clone().unwrap().nonce,
        content,
    );

    save_file_locally(
        file.show_name().clone().as_str(),
        decrypted.unwrap(),
        current_path.to_owned(),
        status,
    )
    .await;
}
