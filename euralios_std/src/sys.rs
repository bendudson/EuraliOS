///! This is mainly from the Rust std library
///! <https://stdrs.dev/nightly/x86_64-unknown-linux-gnu/src/std/sys/unix/path.rs.html>
///!

pub mod path {
    #[inline]
    pub fn is_sep_byte(b: u8) -> bool {
        b == b'/'
    }

    #[inline]
    pub fn is_verbatim_sep(b: u8) -> bool {
        b == b'/'
    }

    pub const MAIN_SEP_STR: &str = "/";
    pub const MAIN_SEP: char = '/';
}
