# Password-Messenger

[![Rust](https://github.com/Poiuy7312/server_example/actions/workflows/rust.yml/badge.svg)](https://github.com/Poiuy7312/server_example/actions/workflows/rust.yml) [![codecov](https://codecov.io/github/Poiuy7312/server_example/graph/badge.svg?token=WJXL81F5N7)](https://codecov.io/github/Poiuy7312/server_example)

This program is designed to take passwords and usernames and store them in a json file. This is to mimic in some fashion how a server or company may store peoples account information.

## Guide

To run this program you need cargo and the rust programming language on your computer. Once you have cargo you can simply run 'cargo run' in the project directory and it will install the dependencies required and compile the code.

### Changing location of password storage

You can do this by setting an environment variable called **ACCOUNTSPATH** to whatever directory you wan't to store it in. 

#### Ex.

- Mac/Linux: `export ACCOUNTSPATH=[Your path here]`
- Windows: `setx ACCOUNTSPATH=[Your path here]`'

### Interacting with the TUI

>💡 You interact with this program through a TUI it tells what buttons to press and what does what this will automatically appear when running the program.

**Create account** will allow you create and store an account while **Login** will allow you to "login" to the program all though this has no real effect on anything

![TUI](/graphics/TUI%20screenshot.jpg)


#### Input account information

Once you get to the screen below you can simply type in a username and password and it will give you a response depending on the mode your in.

![CA_TUI](/graphics/Screenshot%202024-12-12%20204718.jpg)