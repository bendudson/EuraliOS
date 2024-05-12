#![no_std]
#![no_main]

use euralios_std::{print, println, env,
                   syscalls, message};
extern crate alloc;
use alloc::{str, vec, string::String,
            vec::Vec, string::ToString};

// Represents a piece of the file
#[derive(Clone, Copy)]
enum Piece {
    // Start, len [bytes]
    Original{start: usize, len: usize},
    Add{start: usize, len: usize},
}

struct File {
    original: Vec<u8>, // Original contents of the file
    add: Vec<u8>, // Add buffer
    pieces: Vec<Piece>,
}

fn display(file: &File) {
    for piece in &file.pieces {
        let bytes = match piece {
            Piece::Original{start: start,
                            len: len} => {
                &file.original[(*start)..(start + len)]
            },
            Piece::Add{start: start,
                       len: len} => {
                &file.add[(*start)..(start + len)]
            }
        };
        print!("{}", unsafe{str::from_utf8_unchecked(bytes)});
    }
}

#[no_mangle]
fn main() {
    //let args: Vec<String> = env::args().collect();

    for arg in env::args() {
        println!("Arg: {}", arg);
    }

    let mut file = File{
        original: b"test".to_vec(),
        add: b"ing".to_vec(),
        pieces: vec![Piece::Original{start:0,
                                     len:4},
                     Piece::Add{start:0,
                                len:3},]
    };

    display(&file);
    loop {
        match syscalls::receive(&syscalls::STDIN) {
            Ok(syscalls::Message::Short(
                message::CHAR, ch, _)) => {
                // Received a character

                if let Some(c) = char::from_u32(ch as u32) {
                    // Length when encoded as utf8
                    let len_u8s = c.len_utf8();
                    let old_len = file.add.len();

                    file.add.resize(old_len + len_u8s, 0);
                    c.encode_utf8(&mut file.add[old_len..]);

                    let piece = file.pieces[1];
                    match piece {
                        Piece::Original{start: start,
                            len: len} => {
                        },
                        Piece::Add{start: start,
                                   len: len} => {
                            file.pieces[1] = Piece::Add{
                                start:start,
                                len: len + len_u8s
                            };
                        }
                    }
                    // Update display
                    display(&file);
                }
            },
            _ => {
                // Ignore
            }
        }
    }
}

