#![no_std]
#![no_main]

use euralios_std::{println, env};
extern crate alloc;
use alloc::{string::String, vec::Vec};

#[no_mangle]
fn main() {
    //let args: Vec<String> = env::args().collect();

    for arg in env::args() {
        println!("Arg: {}", arg);
    }

    println!("Hello, world!");
}

