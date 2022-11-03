#![no_std]
#![no_main]

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

use euralios_std::{fs::{self, File, OpenOptions},
                   io,
                   message,
                   path::{Path, PathBuf},
                   print, println,
                   syscalls::{self, SyscallError, VFS}};


fn exec_path(path: &Path, vfs: VFS) -> Result<(), SyscallError> {
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
        vfs);

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

    let stdin = io::stdin();
    let mut username = String::new();

    loop {
        print!("login: ");

        username.clear();
        stdin.read_line(&mut username);

        // Here we could ask for a password, compare to hash stored
        // in a password file that users can't directly access.

        // For now just hard-wire some users:
        let vfs = match username.trim() {
            "root" => VFS::shared(), // Root sees everything
            "user" => {
                // Open bin directory read-only
                let bin = OpenOptions::new().open("/ramdisk/bin").unwrap();
                // User's home directory read-write
                let home = OpenOptions::new().write(true).open("/ramdisk/user").unwrap();
                // TCP stack read-write
                let tcp = OpenOptions::new().write(true).open("/tcp").unwrap();
                VFS::new()
                    .mount(bin.to_CommHandle(), "/bin")
                    .mount(home.to_CommHandle(), "/ramdisk")
                    .mount(tcp.to_CommHandle(), "/tcp")
            },
            _ => {
                println!("Unknown login. Try 'root' or 'user'...");
                continue;
            }
        };

        exec_path(Path::new("/ramdisk/bin/shell"), vfs);
    }
}
