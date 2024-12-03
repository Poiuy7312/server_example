pub mod client {
    use age::{encrypt, x25519::Recipient};
    use std::io::{Read, Write};
    use std::net::{Shutdown, TcpStream};

    pub fn send_and_receive(
        mode: &str,
        username: &String,
        password: &String,
        public_key: String,
    ) -> String {
        match connect_to_server() {
            Ok(mut stream) => {
                if mode == "Key" {
                    handle_key_mode(&mut stream)
                } else {
                    handle_encrypted_message_mode(
                        &mut stream,
                        mode,
                        username,
                        password,
                        &public_key,
                    )
                }
            }
            Err(e) => format!("Error connecting: {}", e),
        }
    }

    fn connect_to_server() -> Result<TcpStream, std::io::Error> {
        TcpStream::connect("localhost:8080")
    }

    fn handle_key_mode(stream: &mut TcpStream) -> String {
        let mut buffer = [0; 1024];
        let message = "Key".to_string();
        send_message(stream, &message.as_bytes());
        receive_message(stream, &mut buffer);
        cleanup_stream(stream);

        // Convert the received buffer to the public key string
        String::from_utf8_lossy(&buffer)
            .to_string()
            .trim_end_matches("\0")
            .to_string()
    }

    fn handle_encrypted_message_mode(
        stream: &mut TcpStream,
        mode: &str,
        username: &String,
        password: &String,
        public_key: &str,
    ) -> String {
        let mut buffer = [0; 1024];
        let pub_key: Recipient = public_key.parse().expect("Invalid public key format");
        let message = format!("{},{},{},", mode, username, password);

        let encrypted_message = encrypt_message(&pub_key, &message);
        send_message(stream, &encrypted_message);
        receive_message(stream, &mut buffer);
        cleanup_stream(stream);

        String::from_utf8_lossy(&buffer).to_string()
    }

    pub fn encrypt_message(pub_key: &Recipient, message: &str) -> Vec<u8> {
        let encrypted_message = encrypt(pub_key, message.as_bytes()).expect("Encryption failed");
        let mut encrypted_message = encrypted_message;
        encrypted_message.push(1 as u8); // Appending some additional byte (or other necessary transformations)
        encrypted_message
    }

    fn send_message(stream: &mut TcpStream, message: &[u8]) {
        stream.write_all(message).unwrap();
    }

    fn receive_message(stream: &mut TcpStream, buffer: &mut [u8; 1024]) {
        stream.read(buffer).unwrap();
    }

    fn cleanup_stream(stream: &mut TcpStream) {
        stream.shutdown(Shutdown::Both).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread;

    /*fn mock_server_for_echo() {
        thread::spawn(move || {
            let listener = TcpListener::bind("localhost:8080").unwrap();
            let (mut stream, _) = listener.accept().unwrap();
            let mut buffer = [0; 1024];
            stream.read(&mut buffer).unwrap();
            stream.write_all(&buffer).unwrap();
        });
    } */

    #[test]
    fn test_encrypt_message() {
        let message = "What's up yeah".to_string();
        let key = age::x25519::Identity::generate();
        let public_key = key.to_public();

        // Call the function
        let mut result = client::encrypt_message(&public_key, &message);
        result.pop(); // remove 1 from message that's for the server to worry about
        let decrypted = age::decrypt(&key, result.as_slice()).expect("Couldn't decrypt");
        let decrypted = String::from_utf8_lossy(&decrypted.as_slice()).to_string();
        assert_eq!(message, decrypted)

        // Assert that the result is the echoed message
    }
}
