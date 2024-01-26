use std::clone;
use std::fs;
use std::fs::File;
use std::io::Read;
use std::ops::Deref;
use std::path::Path;

use cliclack::input;
use std::env;

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
    // make a loop to show the tree

    loop {
        // select if you already got an account or not

        let selected: &str = select("Do you have an account ?")
            .item("sign_in", "Yes, let's connect", "")
            .item("sign_up", "Nope, let me discover it", "looser")
            .interact()
            .unwrap();

        // check if you need to sign in or sign up
        match selected {
            // this case handle existing account
            "sign_in" => {
                if let Some((jwt, my_user)) = sign_in().await {
                    navigate_over(my_user, jwt.as_str()).await;
                } else {
                }
            }
            // handle new account
            "sign_up" => {
                if let Some((jwt, my_user)) = sign_up().await {
                    navigate_over(my_user, jwt.as_str()).await;
                }
            }
            _ => log::error("Hmmm you are not supposed to be there").unwrap(),
        }

        /*         log::success(format!("Welcome Mr. {}", my_user.clone().username)).unwrap();
         */
        // items.push(("back", "Back", ""));

        // Do stuff
        log::info("Bye bye").unwrap();
    }
}

async fn navigate_over(mut my_user: User, jwt: &str) {
    let mut current_path: String = "".to_string(); // current path when navigate over the tree
    let mut encrypted_path: String = "".to_string();

    let mut parent_id: String = "".to_string();

    let mut selected_dir: Option<FsEntity> = None;
    let mut items: Vec<(&str, &str, &str)> = Vec::default();

    let mut current_is_shared = false;
    let mut chain_of_dirs: Vec<FsEntity> = Vec::default();

    let mut selected_file: FsEntity = Default::default();
    loop {
        log::info(format!(" -> 📂 You are here: /{}", current_path.clone())).unwrap();

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
            my_user.clone().master_key.clone().asset.unwrap()
        } else {
            selected_dir.as_ref().unwrap().key.asset.clone().unwrap()
        };

        // contains all ref to the dir
        match selected {
            "sign_out" => {
                break;
            }
            "create_dir" => {
                // ask user for a dir name
                let dir_name = get_valid_input("Provide me a directory name", "Name is required!");

                // generate dir -> content:None
                let new_dir =
                    FsEntity::create(dir_name.as_str(), &encrypted_path, None, &parent_id); // so it s a file

                // compute which key will encrypt the dir -> if at root -> user mk else parent dir key

                let encr_dir = new_dir.clone().encrypt(symm_key);

                endpoints::create_dir(jwt, &encr_dir.clone()).await;
            }
            "add_file" => {
                let path = get_valid_input(
                    "Please enter the absolute path of the file you want to add",
                    "Please enter a path.",
                );

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

                endpoints::add_file(jwt, &encrypted_file).await.unwrap();
            }
            "list_content" => {
                //list all folder by names and uid, then get into, and fetch the child from endpoint
                let fetched_dirs: Option<Vec<FsEntity>>;

                // means we are in root so list all

                fetched_dirs = endpoints::get_children(&jwt, parent_id.as_str()).await;
                let mut items: Vec<(String, String, &str)> = Vec::default(); // will contains the item to select
                let mut decrypted_dirs: Vec<FsEntity> = Vec::default(); // will contains the decrypted dirs

                for dir in fetched_dirs.clone().unwrap().iter_mut() {
                    let decrypted_dir = if parent_id.is_empty() {
                        // if parent_id is empty it means we must decrypt with the user master key
                        dir.clone()
                            .decrypt(my_user.clone().master_key.clone().asset.clone().unwrap())
                    } else {
                        dir.clone()
                            .decrypt(selected_dir.as_ref().unwrap().key.clone().asset.unwrap())

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
                        .clone()
                        .is_entity_shared(dir.uid.clone().unwrap().as_str());
                    let shared_status = if current_is_shared { "Shared" } else { "" };

                    items.push((
                        dir.uid.clone().unwrap(),
                        format!("{} {}", icon, name),
                        shared_status,
                    ));
                }

                parent_id = cliclack::select("Pick a item")
                    .items(items.as_ref())
                    .interact()
                    .unwrap();

                // dirty but working
                let back: Option<FsEntity> = selected_dir.clone();

                selected_dir = Some(
                    decrypted_dirs
                        .iter()
                        .find(|d| d.uid.clone().unwrap() == parent_id)
                        .unwrap()
                        .clone(),
                );

                // handle if it is a file
                if selected_dir.as_ref().unwrap().clone().entity_type == "dir" {
                    chain_of_dirs.push(selected_dir.as_ref().unwrap().clone());
                    let encry_selected_dir = fetched_dirs
                        .as_ref()
                        .unwrap()
                        .iter()
                        .find(|d| d.uid.clone().unwrap() == parent_id);

                    current_path =
                        add_to_path(&current_path, &selected_dir.as_ref().unwrap().show_name());
                    encrypted_path = add_to_path(
                        &encrypted_path,
                        &&encry_selected_dir.unwrap().encrypted_name(),
                    );
                } else {
                    // in case of file

                    selected_file = selected_dir.as_ref().unwrap().clone();

                    selected_dir = back;

                    let selected: &str = select("What do you want to do with this file ?")
                        .item("share_file", "Share this file", "")
                        .item("download", "Download it", "")
                        .item("back", "Back", "")
                        .interact()
                        .unwrap();

                    match selected {
                        "share_file" => {
                            let username = get_valid_input(
                                "Please enter the username you want to share the element with",
                                "Please enter a username.",
                            );

                            // get the public key of the user I want to share my dir with
                            let pb_mat = endpoints::get_public_key_with_uid(&jwt, &username).await;

                            // encrypt the dir key with the user public key
                            match crypto::encrypt_asymm(
                                pb_mat.clone().unwrap().public_key.unwrap(),
                                selected_file.key.asset.clone().unwrap(),
                            ) {
                                Ok(encrypted_key) => {
                                    let element_expected_2_be_shared = Sharing {
                                        entity_uid: selected_file.clone().uid.unwrap(),
                                        key: Some(encrypted_key),
                                        owner_id: my_user.clone().uid.clone().unwrap(),
                                        user_id: pb_mat.clone().unwrap().owner_id.unwrap(),
                                    };

                                    endpoints::share_entity(&jwt, &element_expected_2_be_shared)
                                        .await;

                                    my_user.share(&element_expected_2_be_shared);
                                    current_is_shared = true;
                                }
                                Err(e) => {
                                    log::error(format!("Encryption error: {}", e));
                                }
                            }
                        }
                        "download" => {
                            download_decrypted(
                                jwt,
                                &selected_file,
                                my_user.clone().uid.unwrap().as_str(),
                                &current_path,
                            )
                            .await;
                        }
                        "back" => continue,
                        _ => {}
                    }
                }
            }
            "change_password" => {
                let old_1 = get_password_input("🔑Provide your current password");

                let new_1 = get_password_input("🔑Provide a new password");

                // !! must be decrypted before
                let (updated, former_auth_key) = my_user.update_password(&old_1, new_1.as_str());

                if updated.clone().is_none() {
                    log::error(format!("Invalid password, please re-sign in")).unwrap();
                } else {
                    let new_encrypted_user = updated.unwrap().encrypt();

                    endpoints::update_password(&jwt, &new_encrypted_user, former_auth_key.as_str())
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
                if let Some(shared_to_me) = my_user.shared_to_me.as_ref() {
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
                                log::warning("No shared selected yet");
                                for sharing in shared_to_me {
                                    let encrypted_dir =
                                        endpoints::get_shared_entity(jwt.clone(), sharing).await;

                                    if encrypted_dir.is_some() {
                                        log::warning(format!(
                                            "There is {}",
                                            shared_to_me.clone().len()
                                        ));

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
                                    } else {
                                        log::info("There is no content in this directory");
                                    }
                                }
                                // else we are in the share
                            } else {
                                log::warning(format!(
                                    "We are in the shared folder so fetch is sub\n{}\n{}",
                                    selected_shared.as_ref().unwrap().entity_uid,
                                    parent_id.as_str(),
                                ));
                                // must get the children from the selected sharing
                                let fetched_dirs = endpoints::get_shared_children(
                                    &jwt.clone(),
                                    selected_shared.as_ref().unwrap(),
                                    parent_id.as_str(),
                                )
                                .await;
                                if fetched_dirs.is_some() {
                                    for dir in fetched_dirs.clone().unwrap().iter_mut() {
                                        let decrypted_dir = if parent_id.is_empty() {
                                            println!("decrypt with the shared key");
                                            // if parent_id is empty it means are in the top of the share tree
                                            dir.clone().decrypt(
                                                selected_shared.clone().unwrap().key.unwrap(),
                                            )
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
                                            )
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
                                } else {
                                    log::info("There is no content in this directory");
                                }
                            }

                            // the selected folder will be now the current parent
                            parent_id = cliclack::select("Pick a folder")
                                .items(items.as_ref())
                                .interact()
                                .unwrap();
                            log::warning(format!("Dossier selectioné is {}", parent_id));

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
                            selected_dir = Some(
                                decrypted_dirs
                                    .iter()
                                    .find(|d| d.uid.clone().unwrap() == parent_id)
                                    .unwrap()
                                    .clone(),
                            );
                            current_path = add_to_path(
                                &current_path,
                                &selected_dir.as_ref().unwrap().show_name(),
                            );
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
                        .interact()
                        .unwrap();

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
                        log::error(format!("Encryption error: {}", e)).unwrap();
                    }
                }
            }
            "revoke_share" => {
                let share_2_revoke = my_user.find_sharing_by_entity_id(
                    selected_dir.as_ref().unwrap().clone().uid.unwrap().as_str(),
                );

                if share_2_revoke.is_some() {
                    let ok = endpoints::revoke_share(jwt, share_2_revoke.as_ref().unwrap()).await;

                    my_user
                        .revoke_share(selected_dir.as_ref().unwrap().clone().uid.unwrap().as_str());
                    current_is_shared = false;

                    log::success("The share of this item has been revoked successfully").unwrap();
                } else {
                    log::warning("This item is not shared yet").unwrap();
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

                log::error(format!("selected dir: {}", parent_id)).unwrap();
            }
            _ => log::error("Hmmm you are not supposed to be there").unwrap(),
        }
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

fn get_password_input(prompt: &str) -> String {
    password(prompt).mask('🙈').interact().unwrap()
}

async fn save_file_locally(name: &str, content: Vec<u8>, path: String) {
    // Obtenir le chemin du répertoire courant du programme
    let current_dir = env::current_dir().unwrap();

    // Construire le chemin vers le dossier souhaité
    let target_dir = current_dir.join(format!("vault/{}", path));

    // Vérifier si le dossier existe, sinon le créer
    if !Path::new(&target_dir).exists() {
        fs::create_dir_all(&target_dir).unwrap();
    }

    // Construire le chemin complet vers le fichier à enregistrer
    let file_path = target_dir.join(name);

    // Écrire le contenu dans le fichier
    fs::write(file_path, content).unwrap();
}

async fn sign_in() -> Option<(String, User)> {
    let mut spinner = spinner();
    let mut username = "".to_string();

    // Get salt and JWT logic here...

    // Assuming salt and JWT retrieval is successful
    let mut salt: Option<Vec<u8>> = None; // Placeholder for actual salt retrieval
    let mut jwt: Option<String> = None; // Placeholder for actual JWT retrieval
    let mut user: Option<User> = None;

    while salt.is_none() {
        username = get_valid_input("Provide me a username", "Value is required!");

        spinner.start("Getting the salt...");
        salt = endpoints::get_salt(&username).await;

        if salt.is_some() {
            spinner.stop("Salt successfully fetched");
        } else {
            log::error("Invalid credentials").unwrap();
        }
    }

    // Rebuild the secret
    while jwt.is_none() && user.is_none() {
        let usr_password = get_password_input("🔑Provide a password");

        spinner.start("Verifying your account");
        let (auth_key, _) = User::rebuild_secret(&usr_password.clone(), salt.clone());

        log::success("Key rebuilt successfully").unwrap();

        jwt = endpoints::sign_in(&username, auth_key.clone()).await;

        if jwt.is_some() {
            let fetched_user = endpoints::get_user(jwt.clone().unwrap().as_str()).await;

            user = Some(fetched_user.unwrap().decrypt(&usr_password, salt.clone()));

            spinner.stop("Signed in successfully");
        } else {
            log::error("Invalid credentials").unwrap();
        }
    }

    Some((jwt.unwrap(), user.unwrap()))
}

async fn sign_up() -> Option<(String, User)> {
    let mut spinner = spinner();
    let mut user: Option<User> = None;

    // User creation and JWT retrieval logic here...

    // Assuming user creation and JWT retrieval is successful
    let mut jwt = String::from(""); // Placeholder for actual JWT retrieval

    while jwt.is_empty() {
        let username = get_valid_input("Provide a username", "Value is required!");
        let usr_password = get_password_input("🔑Provide a password");
        jwt = endpoints::sign_up(&username, &usr_password).await.unwrap();
        if !jwt.is_empty() {
            spinner.stop("Account successfully created !");
            let fetched_user = endpoints::get_user(jwt.clone().as_str()).await;
            let salt = endpoints::get_salt(&username).await.unwrap();

            user = Some(
                fetched_user
                    .unwrap()
                    .decrypt(&usr_password, Some(salt.clone())),
            );
        }
    }

    Some((jwt, user.unwrap()))
}

fn get_valid_input(prompt: &str, error_msg: &str) -> String {
    // Cloner `error_msg` pour que la fermeture capture sa propre copie
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

async fn download_decrypted(jwt: &str, file: &FsEntity, owner_id: &str, current_path: &str) {
    // create the file fetched from the server
    //get le contenu du fichier de uid
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
    )
    .await;
}

async fn list_decrypted_dir(parent_id: &str) {}
