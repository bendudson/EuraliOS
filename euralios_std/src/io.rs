//! Input/Output

use core::fmt;

extern crate alloc;
use alloc::string::String;

use crate::{syscalls::{self, CommHandle, SyscallError, STDIN, STDOUT},
            message::{self, rcall}};

struct Writer<'a> {
    handle: &'a CommHandle
}

impl fmt::Write for Writer<'_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        if s.len() == 0 {
            return Ok(());
        }
        _ = rcall(self.handle,
                  message::WRITE,
                  (s.len() as u64).into(),
                  syscalls::MemoryHandle::from_u8_slice(s.as_ref()).into(),
                  None);
        Ok(())
    }
}

pub fn _print(handle: &CommHandle, args: fmt::Arguments) {
    use core::fmt::Write;
    Writer{handle}.write_fmt(args).unwrap();
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => ($crate::io::_print(
        &$crate::syscalls::STDOUT, format_args!($($arg)*)));
}

#[macro_export]
macro_rules! println {
    () => ($crate::print!("\n"));
    ($($arg:tt)*) => ($crate::print!("{}\n", format_args!($($arg)*)));
}

#[macro_export]
macro_rules! fprint {
    ($handle:expr, $($arg:tt)*) => ($crate::io::_print(
        $handle, format_args!($($arg)*)));
}

#[macro_export]
macro_rules! fprintln {
    ($handle:expr) => ($crate::fprint!($handle, "\n"));
    ($handle:expr, $($arg:tt)*) => ($crate::fprint!($handle, "{}\n", format_args!($($arg)*)));
}

////////////////////////////////////////////
//

pub struct Stdin {}

/// Constructs a new handle to the standard input of the current process.
///
/// Intended to have the same interface as the Rust std::io
/// <https://doc.rust-lang.org/stable/std/io/fn.stdin.html>
pub fn stdin() -> Stdin {
    Stdin{}
}

impl Stdin {
    /// reads a line of input, appending it to the specified buffer.
    ///
    /// API from <https://doc.rust-lang.org/stable/std/io/trait.BufRead.html#method.read_line>:
    ///
    /// Read all bytes until a newline (the 0xA byte) is reached, and
    /// append them to the provided buffer. You do not need to clear
    /// the buffer before appending.
    ///
    /// This function will read bytes from the underlying stream until
    /// the newline delimiter (the 0xA byte) or EOF is found. Once
    /// found, all bytes up to, and including, the delimiter (if
    /// found) will be appended to buf.
    ///
    /// If successful, this function will return the total number of bytes read.
    ///
    /// If this function returns Ok(0), the stream has reached EOF.
    ///
    /// This function is blocking and should be used carefully: it is
    /// possible for an attacker to continuously send bytes without
    /// ever sending a newline or EOF.
    ///
    pub fn read_line(&self, buf: &mut String) -> Result<usize, SyscallError> {
        let mut length = 0;
        loop {
            match syscalls::receive(&STDIN) {
                Ok(syscalls::Message::Short(
                    message::CHAR, ch, _)) => {
                    // Received a character
                    if ch == 0x8 {
                        // Backspace
                        if let Some(_) = buf.pop() {
                            // If there is a character to remove
                            // Erase by overwriting with a space
                            print!("\u{08} \u{08}");
                        }
                    } else {
                        // Echo character to stdout
                        syscalls::send(&STDOUT, syscalls::Message::Short(
                            message::CHAR, ch, 0));
                        if let Some(utf_ch) = char::from_u32(ch as u32) {
                            // If it's a UTF char then append to buffer
                            buf.push(utf_ch);
                            length += 1;
                            if ch == 0xA {
                                return Ok(length);
                            }
                        }
                    }
                }
                _ => {
                    // Ignore
                }
            }
        }
    }
}

