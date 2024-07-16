#![no_std]
#![no_main]

use euralios_std::{print, env,
                   syscalls, message, console, fs};
extern crate alloc;
use alloc::{str, vec, vec::Vec, string::String};
use core::fmt::{self, Write};

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

// Represents location in a File
#[derive(Clone, Copy)]
struct Cursor {
    piece: usize, // Index of the piece the cursor is in
    pos: usize, // Position inside the piece
}

struct File {
    original: Vec<u8>, // Original contents of the file
    add: Vec<u8>, // Add buffer
    pieces: Vec<Piece>,
    cursor: Cursor,
    path: String,
    changed: bool, // Changed since last save?
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
                    pos: 0},

                path: String::from(path),
                changed: false};
        } else {
            // Doesn't exist (probably)
            return File {
                original: Vec::new(),
                add: Vec::new(),
                pieces: Vec::new(),
                cursor: Cursor {
                    piece: 0,
                    pos: 0},
                path: String::from(path),
                changed: false};
        }
    }

    /// Save contents of File to given path
    fn save(&self) {
        let mut file = fs::File::create(&self.path).expect("Can't open");
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

    // Return byte at given Cursor
    fn at(&self, cursor: Cursor) -> u8 {
        if cursor.piece == self.pieces.len() {
            return 0;
        }
        match self.pieces[cursor.piece] {
            Piece::Original{start: start, ..} =>
                self.original[start + cursor.pos],
            Piece::Add{start: start, ..} =>
                self.add[start + cursor.pos]
        }
    }

    fn next(&self, cursor: Cursor) -> Option<Cursor> {
        if cursor.piece == self.pieces.len() {
            return None; // End of the file
        }
        if cursor.pos == self.pieces[cursor.piece].len() - 1 {
            return Some(Cursor{piece: cursor.piece + 1,
                               pos: 0});
        }
        Some(Cursor{piece: cursor.piece,
                    pos: cursor.pos + 1})
    }

    fn previous(&self, cursor: Cursor) -> Option<Cursor> {
        if cursor.pos == 0 {
            if cursor.piece == 0 {
                return None; // Start of the file
            }
            return Some(Cursor {piece: cursor.piece - 1,
                                pos: self.pieces[cursor.piece - 1].len() - 1});
        }
        Some(Cursor{piece: cursor.piece,
                    pos: cursor.pos - 1})
    }

    fn find(&self, start: Cursor, pattern: u8) -> Option<(Cursor, usize)> {
        // Number of characters traversed
        let mut ntraversed: usize = 0;
        let mut cursor = start;
        loop {
            if let Some(c) = self.next(cursor) {
                cursor = c;
            } else {
                break None;
            }

            // Count characters. NOTE: Assumes ASCII
            ntraversed += 1;

            // Get the byte at this location
            if self.at(cursor) == pattern {
                break Some((cursor, ntraversed));
            }
        }
    }

    // Reverse find, starting from the given cursor
    // If found, returns a Cursor pointing to the location, and the number of characters traversed
    fn rfind(&self, start: Cursor, pattern: u8) -> Option<(Cursor, usize)> {
        // Number of characters traversed
        let mut ntraversed: usize = 0;
        let mut cursor = start;
        loop {
            if let Some(c) = self.previous(cursor) {
                cursor = c;
            } else {
                break None;
            }

            // Count characters. NOTE: Assumes ASCII
            ntraversed += 1;

            // Get the byte at this location
            if self.at(cursor) == pattern {
                break Some((cursor, ntraversed));
            }
        }
    }
}

struct Buffer<'a>(&'a mut [u8], usize);

impl Write for Buffer<'_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let space_left = self.0.len() - self.1;
        if space_left > s.len() {
            self.0[self.1..][..s.len()].copy_from_slice(s.as_bytes());
            self.1 += s.len();
            Ok(())
        } else {
            Err(fmt::Error)
        }
    }
}

fn display(file: &File) {
    // Assemble bytes into a buffer.
    // The buffer is sent to the VGA driver without further copying
    let buffer_limit = 8000; // Maximum number of bytes
    let (mut mem_handle, _) = syscalls::malloc(buffer_limit as u64, 0).unwrap();
    let mut buffer = Buffer(mem_handle.as_mut_slice(buffer_limit), 0);

    // Move cursor to (0,0)
    // Set background to blue (44m); foreground white (37m)
    write!(buffer, "\x1b[H\x1b[44m\x1b[37m  {}", &file.path);
    if file.changed {
        // Foreground yellow (33m)
        write!(buffer, " \x1b[33mchanged\x1b[37m");
    } else {
        write!(buffer, "        ");
    }
    // Clear to the right (K), reset colors
    write!(buffer, "                    \x1b[36m^S Save ^Q Quit\x1b[K\x1b[m\n");

    // Count lines as they are printed
    let mut line_number = 1;
    let mut line_start = true;

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
                &file.add[(*start)..(start + len)]
            }
        };

        let mut write_string = |buffer: &mut Buffer, s: &str| {
            let mut it = s.split('\n').peekable();
            while let Some(line) = it.next() {
                if line_start {
                    write!(buffer, "\x1b[31m{:>4}\x1b[m ", line_number);
                    line_number += 1;
                }
                write!(buffer, "{}", line);
                if it.peek().is_some() {
                    // Clear to the right then newline
                    write!(buffer, "\x1b[K\n");
                }
                line_start = true;
            }
            // The next piece won't start on a new line
            line_start = false;
        };

        // Note:
        // - Add on every end of line \x1b[K to clear the remainder of the line
        // - If cursor position is an EOL, print a ' ' to mark the cursor.
        if piece_index == file.cursor.piece {
            write_string(&mut buffer, unsafe{str::from_utf8_unchecked(&bytes[0 .. file.cursor.pos])});
            if bytes[file.cursor.pos] == b'\n' {
                // Add an extra character to mark the cursor
                write_string(&mut buffer, "\x1b[40m\x1b[37m \x1b[m\n");
            } else {
                write!(buffer, "\x1b[40m\x1b[37m{}\x1b[m",
                       unsafe{str::from_utf8_unchecked(&bytes[file.cursor.pos .. (file.cursor.pos+1)])});
            }
            write_string(&mut buffer, unsafe{str::from_utf8_unchecked(&bytes[(file.cursor.pos + 1)..])});

        } else {
            write_string(&mut buffer, unsafe{str::from_utf8_unchecked(bytes)});
        }
    }
    if file.cursor.piece == file.pieces.len() {
        // Print the cursor
        write!(buffer, "\x1b[40m_\x1b[m");
    }
    // Erase anything below
    write!(buffer, "\x1b[J");

    // Send the buffer
    _ = message::rcall(&syscalls::STDOUT,
                       message::WRITE,
                       (buffer.1 as u64).into(),
                       mem_handle.into(),
                       None);
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
                    // Mark file as changed
                    file.changed = true;
                } else if ch == 15 {
                    // Ctrl-O

                } else if ch == 17 {
                    // Ctrl-Q   => Quit

                    // Move cursor to top left, default colors, erase below
                    print!("\x1b[H\x1b[m\x1b[J");
                    return;

                } else if ch == 19 {
                    // Ctrl-S
                    file.save();
                    file.changed = false;

                } else if ch == 127 {
                    // Delete
                    print!("Delete");

                } else if ch == console::sequences::ArrowUp {
                    // Scan backwards until finding a `\n`
                    if let Some((line_end, mut nchars)) = file.rfind(file.cursor, b'\n') {
                        // Scan backwards again
                        let mut cursor = if let Some((line_start, _)) = file.rfind(line_end, b'\n') {
                            line_start
                        } else {
                            // Start of file
                            nchars -= 1;
                            Cursor{piece: 0, pos: 0}
                        };
                        // Now move forward nchars or until end of line
                        for _ in 0..nchars {
                            cursor = file.next(cursor).unwrap();
                            if file.at(cursor) == b'\n' {
                                break;
                            }
                        }
                        file.cursor = cursor;
                    }
                } else if ch == console::sequences::ArrowDown {
                    // Scan backwards to find the column number
                    let mut nchars = 1;
                    let mut cursor = file.cursor;
                    while let Some(c) = file.previous(cursor) {
                        cursor = c;
                        if file.at(cursor) == b'\n' {
                            break;
                        }
                        nchars += 1;
                    }
                    // Find the next end of line (may already be at the end)
                    if file.at(file.cursor) != b'\n' {
                        if let Some((newline,_)) = file.find(file.cursor, b'\n') {
                            file.cursor = newline;
                        } else {
                            // Cursor is already on the last line
                            continue;
                        }
                    }
                    // Now move forward `nchars`
                    for _ in 0..nchars {
                        if let Some(cursor) = file.next(file.cursor) {
                            file.cursor = cursor;
                            if file.at(cursor) == b'\n' {
                                break;
                            }
                        } else {
                            break;
                        }
                    }

                } else if ch == console::sequences::ArrowRight {
                    // Shift to next character

                    if let Some(cursor) = file.next(file.cursor) {
                        file.cursor = cursor;
                    }
                } else if ch == console::sequences::ArrowLeft {
                    // Shift to previous character

                    if let Some(cursor) = file.previous(file.cursor) {
                        file.cursor = cursor;
                    }
                } else if ch == 27 {
                    // Escape
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
                    // Mark as changed
                    file.changed = true;
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
