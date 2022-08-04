//! Input/Output

use core::fmt;

use crate::{syscalls::{self, CommHandle},
            message::{self, rcall}};

struct Writer<'a> {
    handle: &'a CommHandle
}

impl fmt::Write for Writer<'_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
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
