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

mod client;

fn main() -> Result<()> {
    color_eyre::install()?;
    let terminal = ratatui::init();
    let app_result = App::new().run(terminal);
    ratatui::restore();
    app_result
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

enum AppMode {
    Menu,
    Login,
    CreateAccount,
}
enum InputMode {
    Normal,
    Editing,
}
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
