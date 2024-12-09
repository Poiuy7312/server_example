//! # [Ratatui] User Input example
//!
//! The latest version of this example is available in the [examples] folder in the repository.
//!
//! Please note that the examples are designed to be run against the main branch of the Github
//! repository. This means that you may not be able to compile with the latest release version on
//! crates.io, or the one that you have installed locally.
//!
//! See the [examples readme] for more information on finding examples that match the version of the
//! library you are using.
//!
//! [Ratatui]: https://github.com/ratatui/ratatui
//! [examples]: https://github.com/ratatui/ratatui/blob/main/examples
//! [examples readme]: https://github.com/ratatui/ratatui/blob/main/examples/README.md

// A simple example demonstrating how to handle user input. This is a bit out of the scope of
// the library as it does not provide any input handling out of the box. However, it may helps
// some to get started.
//
// This is a very simple example:
//   * An input box always focused. Every character you type is registered here.
//   * An entered character is inserted at the cursor position.
//   * Pressing Backspace erases the left character before the cursor position
//   * Pressing Enter pushes the current input in the history of previous messages. **Note: ** as
//   this is a relatively simple example unicode characters are unsupported and their use will
// result in undefined behavior.
//
// See also https://github.com/rhysd/tui-textarea and https://github.com/sayanarijit/tui-input/

use ansi_term::Colour::Black;
use color_eyre::Result;
use ratatui::{
    crossterm::event::{self, Event, KeyCode, KeyEventKind},
    layout::{Constraint, Layout},
    style::{Color, Modifier, Style},
    text::Text,
    widgets::{Block, Paragraph},
    DefaultTerminal, Frame,
};
use std::thread;

mod client;
mod server;

fn main() -> Result<()> {
    start_server();
    color_eyre::install()?;
    let terminal = ratatui::init();
    let app_result = App::new().run(terminal);
    ratatui::restore();
    app_result
}

fn start_server() {
    thread::spawn(|| {
        server::server::server_run();
    });
}
/// App holds the state of the application
struct App {
    /// Current value of the input box
    username: String,
    password: String,
    received: String,
    /// Position of cursor in the editor area.
    character_index: usize,
    /// Current input mode
    app_mode: AppMode,
    input_mode: InputMode,
    input_location: InputBox,
}
#[derive(Debug, PartialEq)]
enum AppMode {
    Menu,
    Login,
    CreateAccount,
}
#[derive(Debug, PartialEq)]
enum InputMode {
    Normal,
    Editing,
}
#[derive(Debug, PartialEq)]
enum InputBox {
    Username,
    Password,
}
impl App {
    const fn new() -> Self {
        Self {
            username: String::new(),
            password: String::new(),
            received: String::new(),
            app_mode: AppMode::Menu,
            input_mode: InputMode::Normal,
            input_location: InputBox::Username,
            character_index: 0,
        }
    }
    fn move_cursor_left(&mut self) {
        let cursor_moved_left = self.character_index.saturating_sub(1);
        self.character_index = self.clamp_cursor(cursor_moved_left);
    }

    fn move_cursor_right(&mut self) {
        let cursor_moved_right = self.character_index.saturating_add(1);
        self.character_index = self.clamp_cursor(cursor_moved_right);
    }

    fn enter_char(&mut self, new_char: char) {
        let index = self.byte_index();
        match self.input_location {
            InputBox::Username => self.username.insert(index, new_char),
            InputBox::Password => self.password.insert(index, new_char),
        }
        self.move_cursor_right();
    }

    /// Returns the byte index based on the character position.
    ///
    /// Since each character in a string can be contain multiple bytes, it's necessary to calculate
    /// the byte index based on the index of the character.
    fn byte_index(&self) -> usize {
        match self.input_location {
            InputBox::Username => self
                .username
                .char_indices()
                .map(|(i, _)| i)
                .nth(self.character_index)
                .unwrap_or(self.username.len()),
            InputBox::Password => self
                .password
                .char_indices()
                .map(|(i, _)| i)
                .nth(self.character_index)
                .unwrap_or(self.password.len()),
        }
    }

    fn delete_char(&mut self) {
        let is_not_cursor_leftmost = self.character_index != 0;
        if is_not_cursor_leftmost {
            // Method "remove" is not used on the saved text for deleting the selected char.
            // Reason: Using remove on String works on bytes instead of the chars.
            // Using remove would require special care because of char boundaries.

            let current_index = self.character_index;
            let from_left_to_current_index = current_index - 1;

            // Getting all characters before the selected character.
            match self.input_location {
                InputBox::Username => {
                    let before_char_to_delete =
                        self.username.chars().take(from_left_to_current_index);
                    let after_char_to_delete = self.username.chars().skip(current_index);
                    self.username = before_char_to_delete.chain(after_char_to_delete).collect();
                }
                // Getting all characters after selected character.
                InputBox::Password => {
                    let before_char_to_delete =
                        self.password.chars().take(from_left_to_current_index);
                    let after_char_to_delete = self.password.chars().skip(current_index);

                    // Put all characters together except the selected one.
                    // By leaving the selected one out, it is forgotten and therefore deleted.
                    self.password = before_char_to_delete.chain(after_char_to_delete).collect();
                }
            }
            self.move_cursor_left();
        }
    }

    fn clamp_cursor(&self, new_cursor_pos: usize) -> usize {
        match self.input_location {
            InputBox::Username => new_cursor_pos.clamp(0, self.username.chars().count()),
            InputBox::Password => new_cursor_pos.clamp(0, self.password.chars().count()),
        }
    }

    fn reset_cursor(&mut self) {
        self.character_index = 0;
    }

    fn submit_message(&mut self) {
        match self.input_location {
            InputBox::Username => {
                self.received.clear();
                self.input_location = InputBox::Password;
            }
            InputBox::Password => {
                let username = self.username.clone();
                let password = self.password.clone();
                match self.app_mode {
                    AppMode::CreateAccount => {
                        let mode: &str = "Create";
                        let public_key = client::client::send_and_receive(
                            "Key",
                            &username,
                            &password,
                            "".to_string(),
                        );
                        self.received =
                            client::client::send_and_receive(mode, &username, &password, public_key)
                                .replace("_", format!("{}", Black.paint("_")).as_str())
                    }

                    AppMode::Login => {
                        let mode: &str = "Login";
                        let public_key = client::client::send_and_receive(
                            "Key",
                            &username,
                            &password,
                            "".to_string(),
                        );
                        self.received =
                            client::client::send_and_receive(mode, &username, &password, public_key)
                                .replace("_", format!("{}", Black.paint("_")).as_str())
                    }

                    _ => {}
                }
                self.username.clear();
                self.password.clear();
                self.input_location = InputBox::Username;
            }
        }
        self.reset_cursor();
    }

    fn run(mut self, mut terminal: DefaultTerminal) -> Result<()> {
        loop {
            terminal.draw(|frame| self.draw(frame))?;

            match self.app_mode {
                AppMode::Menu => {
                    if let Event::Key(key) = event::read()? {
                        match key.code {
                            KeyCode::Char('l') => {
                                self.app_mode = AppMode::Login;
                            }
                            KeyCode::Char('c') => {
                                self.app_mode = AppMode::CreateAccount;
                            }
                            KeyCode::Char('q') => {
                                return Ok(());
                            }
                            _ => {}
                        }
                    }
                }
                _ => {
                    if let Event::Key(key) = event::read()? {
                        match self.input_mode {
                            InputMode::Normal => match key.code {
                                KeyCode::Char('e') => {
                                    self.input_mode = InputMode::Editing;
                                }
                                KeyCode::Char('q') => {
                                    return Ok(());
                                }

                                KeyCode::Esc => {
                                    self.app_mode = AppMode::Menu;
                                }
                                _ => {}
                            },
                            InputMode::Editing if key.kind == KeyEventKind::Press => match key.code
                            {
                                KeyCode::Enter => self.submit_message(),
                                KeyCode::Char(to_insert) => self.enter_char(to_insert),
                                KeyCode::Backspace => self.delete_char(),
                                KeyCode::Left => self.move_cursor_left(),
                                KeyCode::Right => self.move_cursor_right(),
                                KeyCode::Esc => self.input_mode = InputMode::Normal,
                                _ => {}
                            },
                            InputMode::Editing => {}
                        }
                    }
                }
            }
        }
    }

    fn draw(&self, frame: &mut Frame) {
        match self.app_mode {
            AppMode::Menu => {
                let instructions =
                    Paragraph::new("Press 'c' to Create Account, 'l' to Login, 'q' to exit")
                        .style(Style::default().fg(Color::Yellow))
                        .block(
                            Block::default()
                                .title("Instructions")
                                .borders(ratatui::widgets::Borders::ALL),
                        );
                frame.render_widget(instructions, frame.area());
            }
            AppMode::CreateAccount => {
                // Improved input area with borders and clear titles
                let vertical = Layout::vertical([
                    Constraint::Length(2), // Space for instructions
                    Constraint::Length(4), // Username input
                    Constraint::Length(4), // Password input
                    Constraint::Min(1),    // Space for sent messages
                ]);

                let [help_area, username_area, password_area, received_area] =
                    vertical.areas(frame.area());

                let text: Text<'_> = Text::from(match self.input_mode {
                    InputMode::Normal => "Press 'q' to exit, 'e' to edit, 'Esc' to go back",
                    InputMode::Editing => "Press 'Esc' to stop editing, 'Enter' to submit",
                })
                .patch_style(Modifier::RAPID_BLINK);
                let help_message = Paragraph::new(text).style(Color::White);
                frame.render_widget(help_message, help_area);

                let user_input = Paragraph::new(self.username.as_str()).block(
                    Block::default()
                        .title("Username")
                        .style(Style::default().fg({
                            match self.input_mode {
                                InputMode::Normal => Color::White,
                                InputMode::Editing => match self.input_location {
                                    InputBox::Username => Color::Yellow,
                                    _ => Color::White,
                                },
                            }
                        }))
                        .borders(ratatui::widgets::Borders::ALL),
                );
                let mut pass_display: String = String::new();

                for _ in 0..self.password.len() {
                    pass_display += "*";
                }
                let pass_input = Paragraph::new(pass_display).block(
                    Block::default()
                        .title("Password")
                        .style(Style::default().fg({
                            match self.input_mode {
                                InputMode::Normal => Color::White,
                                InputMode::Editing => match self.input_location {
                                    InputBox::Password => Color::Yellow,
                                    _ => Color::White,
                                },
                            }
                        }))
                        .borders(ratatui::widgets::Borders::ALL),
                );
                frame.render_widget(user_input, username_area);
                frame.render_widget(pass_input, password_area);
                let received = Paragraph::new(self.received.as_str()).block(
                    Block::default()
                        .title("Received Messages")
                        .style(Style::default().fg(Color::White))
                        .borders(ratatui::widgets::Borders::ALL),
                );
                frame.render_widget(received, received_area);
            }

            AppMode::Login => {
                // Improved input area with borders and clear titles
                let vertical = Layout::vertical([
                    Constraint::Length(2), // Space for instructions
                    Constraint::Length(4), // Username input
                    Constraint::Length(4), // Password input
                    Constraint::Min(1),    // Space for sent messages
                ]);

                let [help_area, username_area, password_area, received_area] =
                    vertical.areas(frame.area());

                let text: Text<'_> = Text::from(match self.input_mode {
                    InputMode::Normal => "Press 'q' to exit, 'e' to edit, 'Esc' to go back",
                    InputMode::Editing => "Press 'Esc' to stop editing, 'Enter' to submit",
                })
                .patch_style(Modifier::RAPID_BLINK);
                let help_message = Paragraph::new(text).style(Color::White);
                frame.render_widget(help_message, help_area);

                let user_input = Paragraph::new(self.username.as_str()).block(
                    Block::default()
                        .title("Username")
                        .style(Style::default().fg({
                            match self.input_mode {
                                InputMode::Normal => Color::White,
                                InputMode::Editing => match self.input_location {
                                    InputBox::Username => Color::Yellow,
                                    _ => Color::White,
                                },
                            }
                        }))
                        .borders(ratatui::widgets::Borders::ALL),
                );
                let mut pass_display: String = String::new();

                for _ in 0..self.password.len() {
                    pass_display += "*";
                }
                let pass_input = Paragraph::new(pass_display).block(
                    Block::default()
                        .title("Password")
                        .style(Style::default().fg({
                            match self.input_mode {
                                InputMode::Normal => Color::White,
                                InputMode::Editing => match self.input_location {
                                    InputBox::Password => Color::Yellow,
                                    _ => Color::White,
                                },
                            }
                        }))
                        .borders(ratatui::widgets::Borders::ALL),
                );
                frame.render_widget(user_input, username_area);
                frame.render_widget(pass_input, password_area);
                let received = Paragraph::new(self.received.as_str()).block(
                    Block::default()
                        .title("Received Messages")
                        .style(Style::default().fg(Color::White))
                        .borders(ratatui::widgets::Borders::ALL),
                );
                frame.render_widget(received, received_area);
            } // Similar enhancements for login mode if needed...
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    // Test Case 1: Test for Entering and Deleting Characters
    #[test]
    fn test_enter_and_delete_characters() {
        let mut app = App::new();

        // Simulate entering a character
        app.enter_char('a');
        assert_eq!(app.username, "a");

        // Simulate deleting the character
        app.delete_char();
        assert_eq!(app.username, "");
    }

    // Test Case 2: Test for Moving Cursor
    #[test]
    fn test_move_cursor() {
        let mut app = App::new();
        app.username = "test".to_string();
        app.character_index = 2; // Start cursor at position 2

        // Move cursor right
        app.move_cursor_right();
        assert_eq!(app.character_index, 3);

        // Move cursor left
        app.move_cursor_left();
        assert_eq!(app.character_index, 2);
    }

    // Test Case 3: Test for Switching Between Input Fields
    #[test]
    fn test_switch_input_location() {
        let mut app = App::new();

        // Enter text in the username field
        app.enter_char('t');
        app.enter_char('e');
        app.enter_char('s');
        app.enter_char('t');
        assert_eq!(app.username, "test");

        // Submit the message and switch to the password field
        app.submit_message();
        assert_eq!(app.input_location, InputBox::Password);
    }

    // Test Case 4: Test for Submitting the Form
    #[test]
    fn test_submit_form() {
        let mut app = App::new();

        // Enter username and password
        app.enter_char('t');
        app.enter_char('e');
        app.enter_char('s');
        app.enter_char('t');
        app.password = "password".to_string();

        // Submit the form
        match app.input_location {
            InputBox::Username => {
                app.submit_message();
                assert_eq!(app.input_location, InputBox::Password);
            }
            InputBox::Password => {
                app.submit_message();
                assert_eq!(app.input_location, InputBox::Username);
            }
        }
        assert_eq!(app.username, "test");
        assert_eq!(app.password, "password");
        // Assert that the fields are cleared
    }

    // Test Case 5: Test for Application Mode Transitions
    #[test]
    fn test_app_mode_transition() {
        let mut app = App::new();

        // Initially in Menu mode
        assert_eq!(app.app_mode, AppMode::Menu);

        // Simulate pressing 'l' for Login
        app.app_mode = AppMode::Login;
        assert_eq!(app.app_mode, AppMode::Login);

        // Simulate pressing 'c' for CreateAccount
        app.app_mode = AppMode::CreateAccount;
        assert_eq!(app.app_mode, AppMode::CreateAccount);
    }

    // Test Case 6: Test for Escape Key Functionality
    #[test]
    fn test_escape_key_functionality() {
        let mut app = App::new();

        // Enter editing mode
        app.input_mode = InputMode::Editing;
        assert_eq!(app.input_mode, InputMode::Editing);

        // Press Escape key to return to normal mode
        app.input_mode = InputMode::Normal;
        assert_eq!(app.input_mode, InputMode::Normal);
    }
    // fn byte_index
    #[test]
    fn test_enter_char_in_password() {
        let mut app = App::new();
        app.input_location = InputBox::Password;

        // Enter character in the password field
        app.enter_char('p');
        assert_eq!(app.password, "p");
    }

    // Test Case 2: Test for byte_index Calculation
    #[test]
    fn test_byte_index() {
        let mut app = App::new();
        app.username = "hello".to_string();
        app.password = "world".to_string();

        // Test byte_index for username
        app.character_index = 2;
        assert_eq!(app.byte_index(), 2);

        // Test byte_index for password
        app.input_location = InputBox::Password;
        app.character_index = 3;
        assert_eq!(app.byte_index(), 3);
    }

    // Test Case 3: Test for Cursor Behavior at Boundaries
    #[test]
    fn test_cursor_at_boundaries() {
        let mut app = App::new();
        app.username = "test".to_string();
        app.character_index = 0;

        // Test moving left when cursor is at the beginning
        app.move_cursor_left();
        assert_eq!(app.character_index, 0);

        // Move cursor to the end
        app.character_index = 4;
        app.move_cursor_right();
        assert_eq!(app.character_index, 4);

        // Test moving right when cursor is at the end
        app.move_cursor_right();
        assert_eq!(app.character_index, 4);
    }

    // Test Case 4: Test for Submitting a Message with Empty Fields
    #[test]
    fn test_submit_empty_message() {
        let mut app = App::new();

        // Initially, username and password are empty
        assert_eq!(app.username, "");
        assert_eq!(app.password, "");

        // Submit the message while username is empty
        app.submit_message();
        assert_eq!(app.input_location, InputBox::Password);
        assert_eq!(app.username, "");
        assert_eq!(app.password, "");

        // Submit again when password is empty
        app.submit_message();
        assert_eq!(app.input_location, InputBox::Username);
        assert_eq!(app.username, "");
        assert_eq!(app.password, "");
    }

    // Test Case 5: Test for Switching Input Location Without Entering Data
    #[test]
    fn test_switch_input_location_without_data() {
        let mut app = App::new();

        // Initially in Username input
        assert_eq!(app.input_location, InputBox::Username);

        // Switch to Password input
        app.submit_message();
        assert_eq!(app.input_location, InputBox::Password);
    }

    // Test Case 6: Test for Moving Cursor with No Text
    #[test]
    fn test_cursor_with_no_text() {
        let mut app = App::new();

        // Start with no text in the input
        app.username = "".to_string();
        app.character_index = 0;

        // Try moving the cursor left and right, even though there's no text
        app.move_cursor_left();
        assert_eq!(app.character_index, 0);

        app.move_cursor_right();
        assert_eq!(app.character_index, 0);
    }
    #[test]
    fn test_server_response_valid_account() {
        server::server::clear_accounts_file();
        let test_user: String = "PReotjiehit2".to_string();
        let test_pass: String = "Minecraft@123".to_string();
        start_server();
        std::thread::sleep(Duration::from_secs(4)); // pause for 2 seconds
        let key_create =
            client::client::send_and_receive("Key", &String::new(), &String::new(), String::new());
        let key_log = key_create.clone();
        let cr_result =
            client::client::send_and_receive("Create", &test_user, &test_pass, key_create);
        let log_result = client::client::send_and_receive("Login", &test_user, &test_pass, key_log);
        server::server::clear_accounts_file();
        assert_eq!(cr_result, format!("AccountCreated::{}", test_user));
        assert_eq!(log_result, format!("Welcome_{}", test_user));
    }
    #[test]
    fn test_server_response_invalid_no_special_char_account() {
        server::server::clear_accounts_file();
        let test_user: String = "PReotjiehit3".to_string();
        let test_pass: String = "Minecraft123".to_string();
        std::thread::sleep(Duration::from_secs(2)); // pause for 2 seconds
        let key =
            client::client::send_and_receive("Key", &String::new(), &String::new(), String::new());
        let result = client::client::send_and_receive("Create", &test_user, &test_pass, key);
        server::server::clear_accounts_file();
        assert_eq!(
            result,
            "Invalid Password: Password_requires_upper_lower_and_special_characters"
        );
    }
    #[test]
    fn test_server_response_invalid_length_account() {
        server::server::clear_accounts_file();
        let test_user: String = "PReotjiehit4".to_string();
        let test_pass: String = "M@1ecra".to_string();
        std::thread::sleep(Duration::from_secs(2)); // pause for 2 seconds
        let key =
            client::client::send_and_receive("Key", &String::new(), &String::new(), String::new());
        let result = client::client::send_and_receive("Create", &test_user, &test_pass, key);
        server::server::clear_accounts_file();
        assert_eq!(result, "Invalid Password: Under_8_characters");
    }
}
