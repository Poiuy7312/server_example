pub(crate) mod client {
    use age::{
        decrypt, encrypt,
        x25519::{Identity, Recipient},
    };
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

    pub(crate) fn connect_to_server() -> Result<TcpStream, std::io::Error> {
        TcpStream::connect("localhost:8080")
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
        let key = age::x25519::Identity::generate();
        let client_pub_key = key.to_public();
        let pub_key: Recipient = public_key.parse().expect("Invalid public key format");
        let message = format!("{},{},{},{}", mode, username, password, client_pub_key);

        let encrypted_message = encrypt_message(&pub_key, &message);
        send_message(stream, &encrypted_message);
        let message = receive_encrypted_message(key, stream, &mut buffer);
        cleanup_stream(stream);

        String::from_utf8_lossy(&message).to_string()
    }

    pub fn encrypt_message(pub_key: &Recipient, message: &str) -> Vec<u8> {
        let encrypted_message = encrypt(pub_key, message.as_bytes()).expect("Encryption failed");
        let mut encrypted_message = encrypted_message;
        encrypted_message.push(1 as u8); // Appending some additional byte (or other necessary transformations)
        encrypted_message
    }

    pub(crate) fn send_message(stream: &mut TcpStream, message: &[u8]) {
        stream.write_all(message).unwrap();
    }

    fn receive_encrypted_message(
        key: Identity,
        stream: &mut TcpStream,
        buffer: &mut [u8; 1024],
    ) -> Vec<u8> {
        stream.read(buffer).unwrap();
        let result = buffer.bytes().into_iter();
        let message = parse_encrypted_message(result);
        let message = decrypt(&key, &message).expect("");
        return message;
    }

    fn receive_message(stream: &mut TcpStream, buffer: &mut [u8; 1024]) {
        stream.read(buffer).unwrap();
    }
    pub(crate) fn cleanup_stream(stream: &mut TcpStream) {
        stream.shutdown(Shutdown::Both).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpStream;
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
    #[test]
    fn test_connect_to_server_failure() {
        // Simulate a server that is not running or unreachable
        let result = client::connect_to_server();

        // Assert that the result is an error
        assert!(result.is_err());
    }
    // Test Case: Simulate the Server Shutdown and Connection Cleanup

    // Test Case: Simulate Timeout or Unreachable Server
    #[test]
    fn test_connect_to_server_timeout() {
        // Try connecting to a non-existent server (simulate timeout)
        let result = TcpStream::connect("localhost:9999");

        // Assert that the connection fails
        assert!(result.is_err(), "Connection should fail due to timeout.");
    }
}
