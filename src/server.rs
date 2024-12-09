pub mod server {
    use age::{
        encrypt,
        secrecy::ExposeSecret,
        x25519::{Identity, Recipient},
    };
    use argon2::{
        // For password hashing and verification using Argon2.
        password_hash::{
            rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
        },
        Argon2,
    };
    use dotenv::dotenv;
    use std::fs::remove_file;
    use std::{
        env,
        fs::File,
        io::{prelude::*, Write},
        net::{TcpListener, TcpStream},
        path::Path,
        sync::LazyLock,
    };

    //use age::x25519::{Identity, Recipient}; For later use
    use regex::Regex; // For regular expression handling.
    use serde_json::{from_str, json, Map, Result, Value}; // For working with JSON data.
    use unicode_segmentation::UnicodeSegmentation; // For handling multi-byte characters in strings.
                                                   // Constant for the file name where account data will be stored.

    static FILE_NAME: LazyLock<String> = LazyLock::new(|| {
        format!(
            "{}{}",
            env::var("ACCOUNTSPATH").unwrap_or_else(|_| String::new()),
            "accounts.txt"
        )
    });
    const ENV_NAME: &str = ".env";

    pub(crate) fn clear_accounts_file() {
        let _ = remove_file(FILE_NAME.as_str());
    }

    // Struct to store account data, including username, password hash, and salt.
    struct Account {
        username: String,
        password_hash: String,
    }

    impl Account {
        // Method to convert Account to a JSON object for storage.
        fn json_rep(&self) -> serde_json::Value {
            json!( {
                "Accounts": {
                    self.username.trim(): {
                        "password": self.password_hash.trim(),
                    }
                }
            })
        }
    }

    fn read_file(file_path: &Path) -> String {
        dotenv().ok();
        let key = std::env::var("KEYACCOUNT").expect("No env variable found");
        let key: Identity = key.parse().expect("Unable to parse data");
        let mut file = File::open(file_path).expect("Unable to open file");
        let mut contents = Vec::new();
        file.read_to_end(&mut contents)
            .expect("Unable to read file");
        let data = age::decrypt(&key, &contents).expect("Can't Decrypt File");
        return String::from_utf8_lossy(&data).to_string();
    }

    // Helper function to parse JSON from a string.
    fn parse_json(contents: &str) -> Value {
        from_str(contents).unwrap_or_else(|_| json!({})) // Return an empty JSON object on error
    }

    fn encrypt_file(json_data: String) -> Vec<u8> {
        let env_path: &Path = Path::new(ENV_NAME);
        match env_path.try_exists() {
            Ok(true) => {
                dotenv().ok();
                let key = std::env::var("KEYACCOUNT").expect("No key env variable found");
                let key: Identity = key.parse().expect("Can't parse to identity");
                let pub_key = key.to_public();
                let data = encrypt(&pub_key, json_data.as_bytes()).expect("Can't encrypt data");
                return data;
            }
            Ok(false) => {
                let key = age::x25519::Identity::generate();
                let pub_key = key.to_public();
                let data = encrypt(&pub_key, json_data.as_bytes()).expect("Can't encrypt data");
                let mut envfile = File::create(ENV_NAME).expect("Unable to create .env file");
                envfile
                    .write_all(format!("KEYACCOUNT={}", key.to_string().expose_secret()).as_bytes())
                    .expect("Write failed");
                return data;
            }
            Err(_) => {
                eprintln!("NOOOOOOOO");
                return Vec::new();
            }
        }
    }

    // Updated `create_file` function to use the refactored helpers.
    fn create_file(data: &Account) {
        let file_path: &Path = Path::new(FILE_NAME.as_str());
        let json_data = data.json_rep();

        // Check if the file already exists.
        match file_path.try_exists() {
            Ok(true) => {
                // If the file exists, open it and append new account data.
                let contents = read_file(file_path); // Use the helper function to read the file
                                                     // Deserialize the JSON file content into a Map.
                let mut json: Map<String, Value> =
                    from_str(&contents).unwrap_or_else(|_| Map::new());

                let account_data = json
                    .entry("Accounts".to_string())
                    .or_insert_with(|| json!(Map::new()));

                // Create a JSON entry for the new account.
                let account_json = json!( {
                    data.username.trim(): {
                        "password": data.password_hash.trim(),
                    }
                });

                // Append the new account data to the existing JSON object.
                account_data
                    .as_object_mut()
                    .unwrap()
                    .extend(account_json.as_object().unwrap().clone());

                // Rewrite the modified JSON data back to the file.
                let mut file = File::create(FILE_NAME.as_str()).expect("Unable to create file");
                let json = json!(json);
                let data = encrypt_file(json.to_string());
                file.write_all(data.as_slice()).expect("Write failed");
            }
            Ok(false) => {
                let mut file = File::create(FILE_NAME.as_str()).expect("Unable to create file");
                let data = encrypt_file(json_data.to_string());
                file.write_all(data.as_slice()).expect("Write failed");
            }
            Err(_) => {}
            _ => eprintln!("Error checking file existence"),
        }
    }

    // Updated `check_username` function to use the refactored helpers.
    fn check_username(username: &str) -> (bool, String) {
        let file_path: &Path = Path::new(FILE_NAME.as_str());
        match file_path.try_exists() {
            Ok(true) => {
                let contents = read_file(file_path); // Use the helper function to read the file
                let json: Value = parse_json(&contents);

                let accounts = json.get("Accounts").unwrap();

                if let Some(_) = accounts.get(username) {
                    // Username is already taken.
                    (false, format!("{username}:_is_already_in_use"))
                } else {
                    // Username is available.
                    (true, "".to_string())
                }
            }
            Ok(false) => (true, "".to_string()), // File does not exist, username is available.
            _ => (true, "".to_string()),         // Error case, assume username is available.
        }
    }

    // Updated `login_to_account` function to use the refactored helpers.
    fn login_to_account(username: &str, password: &str) -> bool {
        let contents = read_file(Path::new(FILE_NAME.as_str())); // Use the helper function to read the file
        let json: Value = parse_json(&contents);

        let accounts = json.get("Accounts").unwrap();
        if let Some(_) = accounts.get(username) {
            let user = accounts.get(username).unwrap();
            let stored_password = user.get("password").unwrap().as_str().unwrap().to_string();
            let password = password.as_bytes();
            let parsed_hash = PasswordHash::new(&stored_password).unwrap();
            match Argon2::default().verify_password(password, &parsed_hash) {
                Ok(()) => true,  // Login successful
                Err(_) => false, // Password mismatch
            }
        } else {
            false // Account not found
        }
    }

    // Function to create a new account by hashing the password and generating a salt.
    fn create_account(username: &str, password: &str) -> Result<Account> {
        // Generate a salt string using OsRng for cryptographic randomness.
        let salt = SaltString::generate(&mut OsRng);
        let argon2: Argon2<'_> = Argon2::default();

        // Convert the username and password to strings and bytes.
        let username = username.to_string();
        let password: &[u8] = password.as_bytes();

        // Hash the password using Argon2 and the generated salt.
        let password_hash: String = argon2.hash_password(password, &salt).unwrap().to_string();

        // Create and return a new Account struct with the hashed password and salt.
        let account = Account {
            username,
            password_hash,
        };

        // Save the new account data to the file.
        create_file(&account);
        Ok(account)
    }

    // Function to validate a password based on predefined criteria.
    fn check_password(password: &str) -> (bool, String) {
        // Use Unicode graphemes to handle multi-byte characters (e.g., emoji).
        let graph_password = password.graphemes(true);
        let length = graph_password.count();

        // Regex to match special characters.
        let special_char = Regex::new(r"[!@#$%^&*()_]").unwrap();

        // Check if the password meets the minimum length requirement.
        if length < 8 {
            let error = "Under_8_characters";
            return (false, format!("Invalid Password: {}", error));
        }

        // Ensure the password does not contain any spaces.
        if password.contains(char::is_whitespace) {
            let error = "Password_has_spaces";
            return (false, format!("Invalid Password: {}", error));
        }

        // Check if the password contains at least one lowercase letter, one uppercase letter,
        // and one special character.
        if password.contains(|arg0: char| char::is_ascii_lowercase(&arg0))
            && password.contains(char::is_uppercase)
            && special_char.is_match(password)
        {
            return (true, String::new()); // Valid password.
        } else {
            let error = "Password_requires_upper_lower_and_special_characters";
            return (false, format!("Invalid Password: {}", error)); // Invalid password.
        }
    }

    fn parse_encrypted_message(message_byte: std::io::Bytes<&[u8]>) -> Vec<u8> {
        let bytes_vec = message_byte
            .filter_map(|byte| byte.ok()) // unwraps and filters out None values
            .collect::<Vec<_>>(); // Collect into a Vec

        let bytes = bytes_vec.as_slice(); // Borrow the Vec as a slice
        let bytes = bytes
            .iter()
            .rev()
            .skip_while(|&&byte| byte != 1 as u8)
            .map(|byte| byte.to_owned())
            .collect::<Vec<_>>(); // Removes all trailing null bytes
        let mut bytes: Vec<_> = bytes.iter().rev().cloned().collect();
        bytes.pop();
        return bytes;
    }
    // Main function that starts the TCP listener and handles incoming connections.
    pub(crate) fn server_run() {
        // Bind the TCP listener to localhost on port 8080.
        let listener = TcpListener::bind("localhost:8080").unwrap();
        let key = age::x25519::Identity::generate();
        let pub_key = key.to_public();
        // Loop to accept incoming connections.
        for stream in listener.incoming() {
            let mut stream: TcpStream = stream.unwrap();

            // Buffer to hold incoming data.
            let mut buffer = [0; 2048];
            stream.read(&mut buffer).unwrap();

            // Convert the received byte buffer to a string.

            let message_bytes = buffer.clone();
            let message_byte: std::io::Bytes<&[u8]> = message_bytes.bytes().into_iter();

            let message: String = String::from_utf8_lossy(&buffer)
                .to_string()
                .trim_matches(char::from(0))
                .to_string();

            // Parse the mode (Create, etc.), username, and password from the received message.
            if message != "Key" {
                let bytes = parse_encrypted_message(message_byte);

                if bytes.len() == 0 {
                    handle_connection(
                        stream,
                        "",
                        "Server received an empty message".to_string(),
                        "",
                    );
                    continue;
                }
                // Removes trailing 1 that is there to signal the end of the encrypted message
                let bytes = bytes.as_slice();
                let message = age::decrypt(&key, bytes);
                match message {
                    Ok(message) => {
                        let account = String::from_utf8_lossy(&message);
                        let account: Vec<&str> = account.split(",").collect();
                        let mode: &str = account[0].trim_matches(char::from(0));
                        let username: &str = account[1].trim_matches(char::from(0));
                        let password: &str = account[2].trim_matches(char::from(0));
                        let client_key: &str = account[3];
                        // Validate the password.
                        let valid_password: (bool, String) = check_password(password);
                        let valid_username: (bool, String) = check_username(username);

                        // Handle the incoming mode.
                        match mode {
                            "Create" => match valid_username.0 {
                                true => match valid_password.0 {
                                    // If password is valid, create the account and send a success response.
                                    true => match create_account(username, password) {
                                        Ok(account) => {
                                            let response: String = format!(
                                                "{}{}",
                                                "AccountCreated::", account.username
                                            );
                                            handle_connection(
                                                stream,
                                                client_key,
                                                response,
                                                "Encrypted",
                                            );
                                        }
                                        Err(err) => {
                                            handle_connection(
                                                stream,
                                                client_key,
                                                err.to_string(),
                                                "Encrypted",
                                            );
                                        }
                                    },
                                    // If password is invalid, send the error message.
                                    false => {
                                        handle_connection(
                                            stream,
                                            client_key,
                                            valid_password.1,
                                            "Encrypted",
                                        );
                                    }
                                },
                                false => {
                                    handle_connection(
                                        stream,
                                        client_key,
                                        valid_username.1,
                                        "Encrypted",
                                    );
                                }
                            },
                            "Login" => {
                                if login_to_account(username, password) {
                                    handle_connection(
                                        stream,
                                        client_key,
                                        format!("Welcome_{}", username),
                                        "Encrypted",
                                    );
                                } else {
                                    handle_connection(
                                        stream,
                                        client_key,
                                        "Username_or_Password_is_Incorrect".to_string(),
                                        "Encrypted",
                                    );
                                }
                            }
                            _ => handle_connection(
                                stream,
                                client_key,
                                "Incorrect_format".to_string(),
                                "Encrypted",
                            ),
                        }
                    }
                    Err(e) => handle_connection(
                        stream,
                        "",
                        format!("Couldn't decrypt information please try again: {e}"),
                        "",
                    ),
                }
            } else {
                handle_connection(stream.try_clone().unwrap(), "", pub_key.to_string(), "");
            }
        }
    }

    // Function to send a message back to the client after processing the request.
    pub(crate) fn handle_connection(
        mut stream: TcpStream,
        client_key: &str,
        message: String,
        mode: &str,
    ) {
        if mode == "Encrypted" {
            let client_key: Recipient = client_key.parse().expect("");
            let mut message = encrypt(&client_key, message.as_bytes()).expect("Encryption failed");
            message.push(1 as u8);

            stream.write(&message).unwrap();
        } else {
            stream.write(&message.as_bytes()).unwrap();
        }
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        use rand::{distributions::Alphanumeric, Rng};
        use serde_json::{from_str, Value};

        // Helper function to clear the accounts file before each test.
        // Test for check_password function
        #[test]
        fn test_check_password_valid() {
            let valid_password = "Valid123!";
            let (is_valid, message) = check_password(valid_password);
            assert!(is_valid);
            assert_eq!(message, "");
        }

        #[test]
        fn test_check_password_invalid_length() {
            let invalid_password = "short1!";
            let (is_valid, message) = check_password(invalid_password);
            assert!(!is_valid);
            assert_eq!(message, "Invalid Password: Under_8_characters");
        }

        #[test]
        fn test_check_password_invalid_no_special_char() {
            let invalid_password = "NoSpecial123";
            let (is_valid, message) = check_password(invalid_password);
            assert!(!is_valid);
            assert_eq!(
                message,
                "Invalid Password: Password_requires_upper_lower_and_special_characters"
            );
        }

        #[test]
        fn test_check_password_with_whitespace() {
            let invalid_password = "Invalid password 123!";
            let (is_valid, message) = check_password(invalid_password);
            assert!(!is_valid);
            assert_eq!(message, "Invalid Password: Password_has_spaces");
        }

        // Test for check_username function
        #[test]
        fn test_check_username_available() {
            clear_accounts_file(); // Ensure the file is clear before testing
            let (is_available, message) = check_username("new_user");
            assert!(is_available);
            assert_eq!(message, "");
        }

        #[test]
        fn test_check_username_taken() {
            // Creating a dummy account for testing
            clear_accounts_file();
            let _ = create_account("existing_user", "Valid123!");

            let (is_available, message) = check_username("existing_user");
            assert!(!is_available);
            assert_eq!(message, "existing_user:_is_already_in_use");
        }

        // Test for create_account function
        #[test]
        fn test_create_account_success() {
            clear_accounts_file(); // Ensure the file is clear before testing

            let account = create_account("new_user", "Valid123!").unwrap();
            assert_eq!(account.username, "new_user");

            // Check if account is saved to file
            let file_path: &Path = Path::new(FILE_NAME.as_str());
            let file = read_file(file_path);
            let file = file.as_str();
            let json: Value = from_str(file).unwrap();
            let accounts = json.get("Accounts").unwrap();
            assert!(accounts.get("new_user").is_some());
        }

        // Test for login_to_account function
        #[test]
        fn test_login_to_account_success() {
            clear_accounts_file(); // Ensure the file is clear before testing

            // Create an account
            let _ = create_account("user1", "Valid123!");

            // Test login with valid credentials
            let result = login_to_account("user1", "Valid123!");
            assert!(result);
        }

        #[test]
        fn test_login_to_account_invalid_password() {
            clear_accounts_file(); // Ensure the file is clear before testing

            // Create an account
            let _ = create_account("user2", "Valid123!");

            // Test login with an incorrect password
            let result = login_to_account("user2", "WrongPassword!");
            assert!(!result);
        }

        #[test]
        fn test_login_to_account_nonexistent_user() {
            clear_accounts_file(); // Ensure the file is clear before testing
            let _ = create_account("User1", "SomePassword!");

            // Test login with a non-existent username
            let result = login_to_account("nonexistent_user", "SomePassword!");
            assert!(!result);
        }
        #[test]
        fn fuzzing_inputs_test() {
            for _ in 1..=20 {
                let mut rng = rand::thread_rng();
                let rand_u_size: u8 = rng.gen_range(1..=50);
                let rand_p_size: u8 = rng.gen_range(8..=100);
                let u: String = rand::thread_rng()
                    .sample_iter(&Alphanumeric)
                    .take(rand_u_size as usize)
                    .map(char::from)
                    .collect();
                let p: String = rand::thread_rng()
                    .sample_iter(&Alphanumeric)
                    .take(rand_p_size as usize)
                    .map(char::from)
                    .collect();
                let _ = create_account(&u, &p);
                let file_path: &Path = Path::new(FILE_NAME.as_str());
                let file = read_file(file_path);
                let file = file.as_str();
                let json: Value = from_str(file).unwrap();
                let accounts = json.get("Accounts").unwrap();
                assert!(accounts.get(&u).is_some());
            }
        }
    }
}

/* Benchmark example:

    use std::time::Instant;
    let now = Instant::now();

    // Code block to measure.
    {
        my_function_to_measure();
    }

    let elapsed = now.elapsed();
    println!("Elapsed: {:.2?}", elapsed);

*/
