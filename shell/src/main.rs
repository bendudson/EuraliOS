#![no_std]
#![no_main]

extern crate alloc;
use alloc::string::String;
use crate::alloc::borrow::ToOwned;

use euralios_std::{io,
                   print, println,
                   syscalls};

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

        println!("Input {}: {}", line_buffer.len(), line_buffer);

        // Convert to a path
        let mut path: String = "/ramdisk/".to_owned();
        path.push_str(&line_buffer.trim());
        println!("Path |{}|", path);

        // Try opening
        match syscalls::open(&path) {
            Ok(handle) => {

            }
            Err(err) => {
                println!("Could not open {}: {}", path, err);
            }
        }

        line_buffer.clear();
    }
}
