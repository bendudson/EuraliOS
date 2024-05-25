#![no_std]
#![no_main]

use euralios_std::{print, println, env,
                   syscalls, message, console, fs};
extern crate alloc;
use alloc::{str, vec, vec::Vec, string::String};

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

impl File {
    /// Open an existing file. If it doesn't exist return an empty File.
    fn open(path: &str) -> File {
        if let Ok(mut file) = fs::File::open(path) {
            let mut buffer = Vec::<u8>::new();
            file.read_to_end(&mut buffer).expect("Couldn't read file");
            let len = buffer.len();
            return File {
                original: buffer,
                add: Vec::new(),
                pieces: vec![Piece::Original{start:0,
                                             len: len}],
                cursor: Cursor {
                    piece: 1,
                    pos: 0}};
        } else {
            // Doesn't exist (probably)
            return File {
                original: Vec::new(),
                add: Vec::new(),
                pieces: Vec::new(),
                cursor: Cursor {
                    piece: 0,
                    pos: 0}};
        }
    }

    /// Save contents of File to given path
    fn save(&self, path: &str) {
        let mut file = fs::File::create(path).expect("Can't open");
        for piece in &self.pieces {
            let bytes = match piece {
                Piece::Original{start: start,
                                len: len} => {
                    &self.original[(*start)..(start + len)]
                },
                Piece::Add{start: start,
                           len: len} => {
                    &self.add[(*start)..(start + len)]
                }
            };
            file.write(bytes);
        }
    }
}

fn display(file: &File) {
    // Move cursor to (0,0)
    print!("\x1b[H");
    // Note: Since we don't erase everything,
    // we need to erase the end of each incomplete line
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
            print!("{}\x1b[40m\x1b[37m{}\x1b[m{}\x1b[m",
                   unsafe{str::from_utf8_unchecked(&bytes[0 .. file.cursor.pos])},
                   unsafe{str::from_utf8_unchecked(&bytes[file.cursor.pos .. (file.cursor.pos+1)])},
                   unsafe{str::from_utf8_unchecked(&bytes[(file.cursor.pos + 1)..])},
            );
        } else {
            print!("{}\x1b[m", unsafe{str::from_utf8_unchecked(bytes)});
        }
    }
    if file.cursor.piece == file.pieces.len() {
        // Print the cursor
        print!("\x1b[40m_\x1b[m");
    }
    // Erase anything below
    print!("\x1b[J");
}

#[no_mangle]
fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        print!("Usage: {} <file>", args[0]);
        return;
    }
    let file_path = &args[1];

    let mut file = File::open(file_path);

    display(&file);
    loop {
        match syscalls::receive(&syscalls::STDIN) {
            Ok(syscalls::Message::Short(
                message::CHAR, ch, _)) => {
                // Received a character

                if ch == 8 {
                    // Backspace
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
                    } else if file.cursor.pos == 1 {
                        // Shorten this piece
                        let piece = file.pieces[file.cursor.piece];
                        match piece {
                            Piece::Original{start: start,
                                            len: len} => {
                                file.pieces[file.cursor.piece] = Piece::Original{
                                    start: start + 1,
                                    len: len - 1
                                };
                            },
                            Piece::Add{start: start,
                                       len: len} => {
                                file.pieces[file.cursor.piece] = Piece::Add{
                                    start: start + 1,
                                    len: len - 1
                                };
                            }
                        }
                        file.cursor.pos = 0;
                    } else {
                        // Split in two
                        let piece = file.pieces[file.cursor.piece];
                        match piece {
                            Piece::Original{start: start,
                                            len: len} => {
                                // First piece
                                file.pieces[file.cursor.piece] = Piece::Original{
                                    start: start,
                                    len: file.cursor.pos - 1
                                };
                                // Second piece
                                file.pieces.insert(file.cursor.piece + 1, Piece::Original{
                                    start: start + file.cursor.pos,
                                    len: len - file.cursor.pos
                                });
                            },
                            Piece::Add{start: start,
                                       len: len} => {
                                // First piece
                                file.pieces[file.cursor.piece] = Piece::Add{
                                    start: start,
                                    len: file.cursor.pos - 1
                                };
                                // Second piece
                                file.pieces.insert(file.cursor.piece + 1, Piece::Add{
                                    start: start + file.cursor.pos,
                                    len: len - file.cursor.pos
                                });
                            }
                        }
                        file.cursor.piece += 1; // Second piece
                        file.cursor.pos = 0;
                    }

                } else if ch == 15 {
                    // Ctrl-O

                } else if ch == 17 {
                    // Ctrl-Q   => Quit
                    return;

                } else if ch == 19 {
                    // Ctrl-S
                    file.save(file_path);

                } else if ch == 127 {
                    // Delete
                    print!("Delete");
                } else if ch == console::sequences::ArrowUp {
                    print!("Arrow Up\n");
                } else if ch == console::sequences::ArrowDown {
                    print!("Arrow Down\n");
                } else if ch == console::sequences::ArrowRight {
                    // Shift to next character

                    if file.cursor.piece == file.pieces.len() {
                        continue;
                    }
                    file.cursor.pos += 1;
                    if file.cursor.pos == file.pieces[file.cursor.piece].len() {
                        // Move to the next piece
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

                    if file.cursor.pos == 0 {
                        // Cursor is at the boundary between pieces
                        // Append to previous piece or insert new

                        if file.cursor.piece == 0 {
                            // Insert
                            file.pieces.insert(file.cursor.piece, Piece::Add{
                                start: old_len,
                                len: len_u8s
                            });
                            file.cursor.piece = 1;

                        } else {
                            let piece = file.pieces[file.cursor.piece - 1];
                            match piece {
                                Piece::Original{start: _start,
                                                len: _len} => {
                                    // Insert
                                    file.pieces.insert(file.cursor.piece, Piece::Add{
                                        start: old_len,
                                        len: len_u8s
                                    });
                                    file.cursor.piece += 1;
                                },
                                Piece::Add{start: start,
                                           len: len} => {
                                    if start + len == old_len {
                                        // Piece is at the end of the Add buffer => append
                                        file.pieces[file.cursor.piece - 1] = Piece::Add{
                                            start: start,
                                            len: len + len_u8s
                                        };
                                    } else {
                                        // Piece is not at the end of Add buffer
                                        // => Create a new Add piece
                                        file.pieces.insert(file.cursor.piece, Piece::Add{
                                            start: old_len,
                                            len: len_u8s
                                        });
                                        file.cursor.piece += 1;
                                    }
                                }
                            }
                        }
                    } else {
                        // Cursor in the middle of a piece
                        // => Split piece in two

                        let piece = file.pieces[file.cursor.piece];
                        match piece {
                            Piece::Original{start: start,
                                            len: len} => {
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

                                file.cursor.piece += 2; // Shift to 2nd half
                                file.cursor.pos = 0;
                            },
                            Piece::Add{start: start,
                                       len: len} => {
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

                                file.cursor.piece += 2; // Shift to 2nd half
                                file.cursor.pos = 0;
                            }
                        }
                    }
                }
                // Update display
                display(&file);
                print!("\nReceived: {}", ch);
                print!("\n\n Number of pieces: {}  cursor piece {} pos {}",
                       file.pieces.len(), file.cursor.piece, file.cursor.pos);
            },
            _ => {
                // Ignore
            }
        }
    }
}
