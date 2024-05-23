#![no_std]
#![no_main]

use euralios_std::{print, println, env,
                   syscalls, message, console};
extern crate alloc;
use alloc::{str, vec, vec::Vec};

// Represents a piece of the file
#[derive(Clone, Copy)]
enum Piece {
    // Start, len [bytes]
    Original{start: usize, len: usize},
    Add{start: usize, len: usize},
}

impl Piece {
    fn len(&self) -> usize {
        match *self {
            Piece::Original{len: len, ..} => len,
            Piece::Add{len: len, ..} => len,
        }
    }
}

struct Cursor {
    piece: usize, // Index of the piece the cursor is in
    pos: usize, // Position inside the piece
}

struct File {
    original: Vec<u8>, // Original contents of the file
    add: Vec<u8>, // Add buffer
    pieces: Vec<Piece>,
    cursor: Cursor,
}

fn display(file: &File) {
    // Move cursor to (0,0) then erase below 
    print!("\x1b[H\x1bJ");
    for (piece_index, piece) in file.pieces.iter().enumerate() {
        let bytes = match piece {
            Piece::Original{start: start,
                            len: len} => {
                &file.original[(*start)..(start + len)]
            },
            Piece::Add{start: start,
                       len: len} => {
                print!("\x1b[31m"); // Set foreground to red
                &file.add[(*start)..(start + len)]
            }
        };

        if piece_index == file.cursor.piece {
            if file.cursor.pos != bytes.len() {
                print!("{}\x1b[40m{}\x1b[49m{}\x1b[m",
                       unsafe{str::from_utf8_unchecked(&bytes[0 .. file.cursor.pos])},
                       unsafe{str::from_utf8_unchecked(&bytes[file.cursor.pos .. (file.cursor.pos+1)])},
                       unsafe{str::from_utf8_unchecked(&bytes[(file.cursor.pos + 1)..])},
                );
            } else {
                print!("{}\x1b[40m_\x1b[m", unsafe{str::from_utf8_unchecked(bytes)});
            }
        } else {
            print!("{}\x1b[m", unsafe{str::from_utf8_unchecked(bytes)});
        }
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
                                len:3},],
        cursor: Cursor {piece: 1,
                        pos: 3} // End of the piece
    };

    display(&file);
    loop {
        match syscalls::receive(&syscalls::STDIN) {
            Ok(syscalls::Message::Short(
                message::CHAR, ch, _)) => {
                // Received a character

                print!("Received: {}", ch);

                if ch == 8 {
                    // Backspace
                    print!("Backspace");

                    if file.cursor.pos == 0 {
                        // Shorten the piece before this
                        if file.cursor.piece == 0 {
                            continue; // no-op
                        }
                        let piece = file.pieces[file.cursor.piece - 1];
                        match piece {
                            Piece::Original{start: start,
                                            len: len} => {
                                if len == 1 {
                                    // Remove the piece
                                    file.pieces.remove(file.cursor.piece - 1);
                                    file.cursor.piece -= 1;
                                } else {
                                    file.pieces[file.cursor.piece - 1] = Piece::Original{
                                        start: start,
                                        len: len - 1};
                                }
                            },
                            Piece::Add{start: start,
                                       len: len} => {
                                if len == 1 {
                                    // Remove the piece
                                    file.pieces.remove(file.cursor.piece - 1);
                                    file.cursor.piece -= 1;
                                } else {
                                    file.pieces[file.cursor.piece - 1] = Piece::Add{
                                        start: start,
                                        len: len - 1};
                                }
                            },
                        }
                    } else {
                        let piece = file.pieces[file.cursor.piece];
                        match piece {
                            Piece::Original{start: start,
                                            len: len} => {
                                // Split in two
                            },
                            Piece::Add{start: start,
                                       len: len} => {
                            }
                        }
                    }
                } else if ch == 127 {
                    // Delete
                    print!("Delete");
                } else if ch == console::sequences::ArrowUp {
                    print!("Arrow Up\n");
                } else if ch == console::sequences::ArrowDown {
                    print!("Arrow Down\n");
                } else if ch == console::sequences::ArrowRight {
                    // Shift to next character
                    let piece_len = file.pieces[file.cursor.piece].len();
                    if file.cursor.pos < piece_len {
                        file.cursor.pos += 1;
                    }
                    if ((file.cursor.pos == piece_len) &&
                        (file.cursor.piece != file.pieces.len() - 1)) {
                        // Move to the next piece
                        // Only on the last piece can pos == piece_len
                        file.cursor.piece += 1;
                        file.cursor.pos = 0;
                    }
                } else if ch == console::sequences::ArrowLeft {
                    // Shift to previous character
                    if file.cursor.pos == 0 {
                        // At beginning of piece
                        if file.cursor.piece > 0 {
                            file.cursor.piece -= 1;
                            file.cursor.pos = file.pieces[file.cursor.piece].len() - 1;
                        }
                    } else  {
                        file.cursor.pos -= 1;
                    }
                } else if let Some(c) = char::from_u32(ch as u32) {
                    // Extend the Add buffer and insert character into it
                    let len_u8s = c.len_utf8();
                    let old_len = file.add.len();

                    file.add.resize(old_len + len_u8s, 0);
                    c.encode_utf8(&mut file.add[old_len..]);

                    let piece = file.pieces[file.cursor.piece];
                    match piece {
                        Piece::Original{start: start,
                                        len: len} => {
                            // Need to create a new Add piece
                            if file.cursor.pos == 0 {
                                // Cursor at the start => Insert before
                                file.pieces.insert(file.cursor.piece, Piece::Add{
                                    start: old_len,
                                    len: len_u8s
                                });
                                file.cursor.pos = len_u8s;
                            } else if file.cursor.pos == len {
                                // End of piece => Insert after
                                file.cursor.piece += 1;
                                file.pieces.insert(file.cursor.piece, Piece::Add{
                                    start: old_len,
                                    len: len_u8s
                                });
                                file.cursor.pos = len_u8s;
                            } else {
                                // Middle of piece => Split

                                // Second half of the original piece
                                file.pieces[file.cursor.piece] = Piece::Original{
                                    start: start + file.cursor.pos,
                                    len: len - file.cursor.pos
                                };
                                // New piece
                                file.pieces.insert(file.cursor.piece, Piece::Add{
                                    start: old_len,
                                    len: len_u8s
                                });
                                // First half of the original piece
                                file.pieces.insert(file.cursor.piece, Piece::Original{
                                    start: start,
                                    len: file.cursor.pos
                                });

                                file.cursor.piece += 1; // Shift to new piece
                                file.cursor.pos = len_u8s;
                            }
                        },
                        Piece::Add{start: start,
                                   len: len} => {
                            if file.cursor.pos == len {
                                // Cursor is at the end of this piece
                                if start + len == old_len {
                                    // Piece is at the end of the Add buffer
                                    file.pieces[file.cursor.piece] = Piece::Add{
                                        start: start,
                                        len: len + len_u8s
                                    };
                                    file.cursor.pos += len_u8s;
                                } else {
                                    // Piece is not at the end of Add buffer
                                    // => Create a new Add piece
                                    file.cursor.piece = file.pieces.len();
                                    file.cursor.pos = len_u8s;
                                    file.pieces.push(Piece::Add{
                                        start: old_len,
                                        len: len_u8s
                                    });
                                }
                            } else if file.cursor.pos == 0 {
                                // Cursor at start of piece => Insert
                                file.pieces.insert(file.cursor.piece, Piece::Add{
                                    start: old_len,
                                    len: len_u8s
                                });
                                file.cursor.pos = len_u8s;
                            } else {
                                // Cursor in the middle
                                // => Split piece in two

                                // Second half of the original piece
                                file.pieces[file.cursor.piece] = Piece::Add{
                                    start: start + file.cursor.pos,
                                    len: len - file.cursor.pos
                                };
                                // New piece
                                file.pieces.insert(file.cursor.piece, Piece::Add{
                                    start: old_len,
                                    len: len_u8s
                                });
                                // First half of the original piece
                                file.pieces.insert(file.cursor.piece, Piece::Add{
                                    start: start,
                                    len: file.cursor.pos
                                });

                                file.cursor.piece += 1; // Shift to new piece
                                file.cursor.pos = len_u8s;
                            }
                        }
                    }
                }
                // Update display
                display(&file);
            },
            _ => {
                // Ignore
            }
        }
    }
}

