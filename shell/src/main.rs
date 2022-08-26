#![no_std]
#![no_main]

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;
use crate::alloc::borrow::ToOwned;

use euralios_std::{path::Path,
                   fs::{self, File},
                   io,
                   message,
                   print, println,
                   syscalls::{self, SyscallError}};

fn exec_path(path: &str) -> Result<(), SyscallError> {
    let mut file = File::open(&path)?;

    let mut bin: Vec<u8> = Vec::new();
    file.read_to_end(&mut bin)?;

    // Create a communication handle for the input
    let (exe_input, exe_input2) = syscalls::new_rendezvous()?;

    syscalls::exec(
        &bin,
        0, // Permission flags
        exe_input2,
        syscalls::STDOUT.clone());

    loop {
        // Wait for keyboard input
        match syscalls::receive(&syscalls::STDIN) {
            Ok(syscalls::Message::Short(
                message::CHAR, ch, _)) => {
                // Received a character
                if let Err((err, _)) = syscalls::send(&exe_input,
                                                 syscalls::Message::Short(
                                                     message::CHAR, ch, 0)) {
                    println!("Received error: {}", err);
                    return Ok(());
                }
            },
            _ => {
                // Ignore
            }
        }
    }
}

#[no_mangle]
fn main() {
    println!("Welcome to EuraliOS shell!

  [Esc] switches to system console
  [Tab] returns to this console
");

    let stdin = io::stdin();
    let mut line_buffer = String::new();
    loop {
        // prompt
        print!("$ ");

        // Read a line of input
        stdin.read_line(&mut line_buffer);
        let input = line_buffer.trim();

        if input == "ls" {
            if let Ok(rd) = fs::read_dir("/ramdisk") {
                for entry in rd {
                    println!("{}", entry.unwrap().file_name());
                }
            }
        } else if input.len() > 0 {
            // Convert to a path
            let mut path: String = "/ramdisk/".to_owned();
            path.push_str(input);
            println!("Path |{}|", path);

            if let Err(err) = exec_path(&path) {
                println!("Couldn't open '{}'", path);
            }
        }

        line_buffer.clear();
    }
}
