# Client for server encryption shared filesystem
This repo contains the end-client that allows you to interact with the shared encrypted drive running on a server.

The aim of this project is to be able to create an account and upload/download files and folders on a online storage. All the data are end-to-end encrypted.

For more details about the security model [have a look there](https://maxime.chantemargue.ch/projects/sharing_encrypted_file_system).

> [!TIP]  
> To run this client you must [run the server before](https://github.com/CSharper63/server_encryption_file_system)


## What can you do ?
- Create an account
- Change password
- Create folder
- Add file
- Share file/folder

## How to run
```bash
cargo run --release
```

> [!CAUTION] 
> This application is currently under refactoring, you may get some issue while executing it.