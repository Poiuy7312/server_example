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

    pub(crate) fn connect_to_server() -> Result<TcpStream, std::io::Error> {
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

    pub(crate) fn send_message(stream: &mut TcpStream, message: &[u8]) {
        stream.write_all(message).unwrap();
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
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread;
    use std::time::Duration;

    fn mock_server_for_echo() -> thread::JoinHandle<()> {
        thread::spawn(move || {
            let listener = TcpListener::bind("localhost:8080").unwrap();
            let (mut stream, _) = listener.accept().unwrap();
            let mut buffer = [0; 1024];
            stream.read(&mut buffer).unwrap();
            stream.write_all(&buffer).unwrap();
        })
    }
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
        assert!(
            result.is_err(),
            "Expected an error when connecting to an unreachable server."
        );
    }

    // Test Case 2: Test Cleanup Stream
    #[test]
    fn test_cleanup_stream() {
        // Spin up a mock echo server for testing
        mock_server_for_echo();

        // Connect to the mock server
        let mut stream = client::connect_to_server().expect("Failed to connect to server.");

        // Send a message to the server
        let test_message = "Hello Server".to_string();
        client::send_message(&mut stream, test_message.as_bytes());

        // Call cleanup_stream to properly shut down the connection
        client::cleanup_stream(&mut stream);

        // Sleep briefly to ensure the connection is properly shut down
        thread::sleep(Duration::from_secs(1));

        // Since the server is a simple echo server, we can't directly verify the shutdown,
        // But we can check if the stream is closed by trying to use it after cleanup.
        let result = stream.write_all(b"test");

        // The stream should no longer be usable, and this should return an error.
        assert!(result.is_err(), "Stream should be closed after cleanup.");
    }

    // Test Case: Simulate the Server Shutdown and Connection Cleanup
    #[test]
    fn test_server_shutdown_cleanup() {
        // Simulate the server shutdown after a short period
        let server_thread = thread::spawn(move || {
            let listener = TcpListener::bind("localhost:8080").unwrap();
            let (mut stream, _) = listener.accept().unwrap();
            let mut buffer = [0; 1024];
            stream.read(&mut buffer).unwrap();
            stream.write_all(&buffer).unwrap();
            // Server simulates shutdown after sending response
            drop(stream); // Explicitly close the server connection here
        });

        // Give server some time to start
        thread::sleep(Duration::from_secs(1));

        // Connect to the mock server
        let mut stream = client::connect_to_server().expect("Failed to connect to server.");

        // Send a test message
        let test_message = "Hello Server".to_string();
        client::send_message(&mut stream, test_message.as_bytes());

        // Simulate server shutdown
        server_thread.join().unwrap();

        // Call cleanup_stream to ensure the connection is properly closed
        client::cleanup_stream(&mut stream);

        // After cleanup, try to write to the stream to assert it's closed
        let result = stream.write_all(b"test");

        // The stream should be closed, so this should fail
        assert!(
            result.is_err(),
            "Stream should be closed after server shutdown and cleanup."
        );
    }

    // Test Case: Simulate Timeout or Unreachable Server
    #[test]
    fn test_connect_to_server_timeout() {
        // Try connecting to a non-existent server (simulate timeout)
        let result = TcpStream::connect("localhost:9999");

        // Assert that the connection fails
        assert!(result.is_err(), "Connection should fail due to timeout.");
    }
}
