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

fn ls(current_directory: &str, args: Vec<&str>) {
    if args.len() > 1 {
        println!("Usage: ls [path]");
        return;
    }

    let option_rd = if args.len() == 0 {
        fs::read_dir(current_directory)
    } else {
        let path = Path::new(args[0]);
        if path.is_absolute() {
            fs::read_dir(path)
        } else {
            // Join paths
            fs::read_dir(current_directory)
        }
    };

    if let Ok(rd) = option_rd {
        for entry in rd {
            println!("{}", entry.unwrap().file_name());
        }
    }
}

#[no_mangle]
fn main() {
    println!("Welcome to EuraliOS shell!

  [Esc] switches to system console
  [Tab] returns to this console

Type help [Enter] to see the shell help page.
");

    let stdin = io::stdin();
    let mut line_buffer = String::new();

    // Current Working Directory
    let mut current_directory = String::from("/ramdisk");

    loop {
        // prompt
        print!("$ ");

        // Read a line of input
        stdin.read_line(&mut line_buffer);

        let mut line_iter = line_buffer.split_whitespace();
        if let Some(command) = line_iter.next() {
            let args: Vec<_> = line_iter.collect();
            match command {
                // Built-in shell commands
                //
                // Help
                "help" | "?" => {
                    println!(
"EuraliOS shell help

* Built-in commands:
  ls     List directory
  cd     Change directory
  pwd    Print working directory");
                },
                // List directory
                "ls" => ls(&current_directory, args),
                // Print working directory
                "pwd" => println!("{}", current_directory),
                // Change directory
                "cd" => {
                    println!("Args: {:?}", args);
                },
                cmd => {
                    let mut path: String = current_directory.clone();
                    path.push_str(cmd);
                    println!("Path |{}|", path);

                    if let Err(err) = exec_path(&path) {
                        println!("Couldn't open '{}'", path);
                    }
                }
            }
        }

        line_buffer.clear();
    }
}
