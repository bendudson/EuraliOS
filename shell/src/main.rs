#![no_std]
#![no_main]

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;
use core::str;

use euralios_std::{path::{Path, PathBuf},
                   fs::{self, File},
                   io,
                   message,
                   print, println,
                   syscalls::{self, SyscallError, VFS}};

fn exec_path(path: &Path, args: Vec<&str>) -> Result<(), SyscallError> {
    // Read binary from file
    let bin = {
        let mut bin: Vec<u8> = Vec::new();
        let mut file = File::open(path)?;
        file.read_to_end(&mut bin)?;
        bin
    };

    // Create a communication handle for the input
    let (exe_input, exe_input2) = syscalls::new_rendezvous()?;

    syscalls::exec(
        &bin,
        0, // Permission flags
        exe_input2,
        syscalls::STDOUT.clone(),
        VFS::shared(),
        args)?;

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

fn help() {
    println!(
"EuraliOS shell help

* Console windows
  F1              System processes
  F2..F5          User consoles

* Built-in commands:
  ls [<path>]     List directory
  cd <path>       Change directory
  pwd             Print working directory
  rm <file>       Delete a file
  mount           List mounted filesystems
  umount <path>   Un-mount a filesystem
  mkdir <path>    Make a directory
  exit            Exit shell
"
    );
}

/// List a directory
fn ls(current_directory: &Path, args: &[&str]) {
    if args.len() > 1 {
        println!("Usage: ls [path]");
        return;
    }

    let option_rd = if args.len() == 0 {
        fs::read_dir(current_directory)
    } else {
        let path = fs::canonicalize(PathBuf::from(current_directory).join(args[0])).unwrap();
        fs::read_dir(path)
    };

    if let Ok(rd) = option_rd {
        for entry in rd {
            if let Ok(obj) = entry {
                if obj.metadata().unwrap().is_dir() {
                    println!("\x1b[34m{}\x1b[m", obj.file_name());
                } else {
                    println!("{}", obj.file_name());
                }
            }
        }
    }
}

/// Unmount a path
fn umount(args: &[&str]) {
    if args.len() != 1 {
        println!("Usage: umount <path>");
        return;
    }
    let path = args.first().unwrap(); // We know it has one element
    if let Err(err) = syscalls::umount(path) {
        println!("umount error: {}", err);
    }
}

/// Delete a file
fn rm(current_directory: &Path, args: &[&str]) {
    if args.len() != 1 {
        println!("Usage: rm <file>");
        return;
    }
    let file = args.first().unwrap();

    let path = fs::canonicalize(PathBuf::from(current_directory).join(file)).unwrap();
    if let Err(err) = fs::remove_file(path) {
        // Failed
        println!("rm: cannot remove {}: {}", file, err);
    }
}

/// Make a directory
fn mkdir(current_directory: &Path, args: &[&str]) {
    if args.len() != 1 {
        println!("Usage: mkdir <directory>");
        return;
    }
    let arg = args.first().unwrap();
    let path = fs::canonicalize(PathBuf::from(current_directory).join(arg)).unwrap();
    if let Err(err) = fs::create_dir(path) {
        // Failed
        println!("mkdir: cannot create {}: {:?}", arg, err);
    }
}

#[no_mangle]
fn main() {
    println!("Type help [Enter] to see the shell help page.");

    let stdin = io::stdin();
    let mut line_buffer = String::new();

    // Current Working Directory
    let mut current_directory = PathBuf::from("/ramdisk");

    loop {
        // prompt
        print!("$ ");

        // Read a line of input
        stdin.read_line(&mut line_buffer);

        let mut args: Vec<_> = line_buffer.split_whitespace().collect();
        if let Some(command) = args.first() {
            match *command {
                // Built-in shell commands
                //
                // Help
                "help" | "?" => help(),
                // List directory
                "ls" => ls(&current_directory, &args[1..]),
                // Print working directory
                "pwd" => println!("{:?}", current_directory),
                // Change directory
                "cd" => {
                    if args.len() != 2 {
                        println!("Usage: cd <directory>");
                        continue;
                    }
                    current_directory.push(args[1]);
                    current_directory = fs::canonicalize(current_directory).unwrap();
                },
                "mount" => {
                    match syscalls::list_mounts() {
                        Ok((handle, len)) =>  {
                            let u8_slice = handle.as_slice::<u8>(len as usize);
                            if let Ok(s) = str::from_utf8(u8_slice) {
                                println!("{}", s);
                            } else {
                                println!("mount: syscall utf8 error");
                            }
                        }
                        Err(err) => {
                            println!("mount: error {}", err);
                        }
                    }
                },
                "umount" => umount(&args[1..]),
                "rm" => rm(&current_directory, &args[1..]),
                "mkdir" => mkdir(&current_directory, &args[1..]),
                "exit" => return,
                cmd => {
                    let path = fs::canonicalize(current_directory.join(cmd)).unwrap();

                    if let Err(err) = exec_path(&path, args) {
                        println!("Couldn't open '{:?}': {}", path, err);
                    }
                }
            }
        }

        line_buffer.clear();
    }
}
