pub mod client {
    use age::{encrypt, x25519::Recipient};
    use std::io::{Read, Write};
    use std::net::{Shutdown, TcpStream}; // 0.8

    pub fn send_and_receive(
        mode: &str,
        username: &String,
        password: &String,
        public_key: String,
    ) -> String {
        let stream = TcpStream::connect("localhost:8080");
        match stream {
            Ok(mut stream) => {
                if mode == "Key" {
                    let mut buffer = [0; 1024];

                    let message: String = "Key".to_string();
                    stream.write_all(message.as_bytes()).unwrap();
                    stream.read(&mut buffer).unwrap();
                    stream.shutdown(Shutdown::Both).unwrap();
                    let pub_key = String::from_utf8_lossy(&buffer)
                        .to_string()
                        .trim_end_matches("\0")
                        .to_string();
                    return pub_key;
                } else {
                    let mut buffer = [0; 1024];
                    let pub_key: Recipient = public_key.parse().expect("Couldn't");
                    let message = format!("{},{},{},", mode, username, password);
                    let mut encrypted_message: Vec<u8> =
                        encrypt(&pub_key, message.as_bytes()).expect("Invalid public key");
                    encrypted_message.push(1 as u8);
                    let encrypted_message = encrypted_message;
                    stream.write_all(&encrypted_message).unwrap();
                    stream.read(&mut buffer).unwrap();
                    stream.shutdown(Shutdown::Both).unwrap();
                    return String::from_utf8_lossy(&buffer).to_string();
                    /*let u: String = rand::thread_rng()
                        .sample_iter(&Alphanumeric)
                        .take(7)
                        .map(char::from)
                        .collect();
                    let p: String = rand::thread_rng()
                        .sample_iter(&Alphanumeric)
                        .take(7)
                        .map(char::from)
                        .collect();*/
                }
            }
            Err(e) => {
                return format!("Error connecting: {}", e);
            }
        }
    }
}
