///! Path manipulation
///!
///! Intended to implement https://doc.rust-lang.org/std/path/index.html
///!

use core::convert::AsRef;
use core::marker::Sized;
extern crate alloc;
use alloc::string::String;

/// A slice of a path
pub struct Path {
    inner: str,
}

impl Path {
    /// Directly wraps a string slice as a Path slice.
    ///
    /// This is a cost-free conversion.
    pub fn new<S: AsRef<str> + ?Sized>(s: &S) -> &Path {
        unsafe { &*(s.as_ref() as *const str as *const Path) }
    }

    /// Yields the underlying str slice.
    pub fn as_os_str(&self) -> &str {
        &self.inner
    }

    /// true if the path starts with '/'
    pub fn has_root(&self) -> bool {
        self.inner.as_bytes()[0] == b'/'
    }

    /// Returns true if the Path is absolute, i.e., if it is
    /// independent of the current directory.
    pub fn is_absolute(&self) -> bool {
        self.has_root()
    }

    /// Returns true if the Path is relative, i.e., not absolute.
    pub fn is_relative(&self) -> bool {
        !self.is_absolute()
    }
}

impl AsRef<Path> for str {
    #[inline]
    fn as_ref(&self) -> &Path {
        Path::new(self)
    }
}

impl AsRef<Path> for String {
    #[inline]
    fn as_ref(&self) -> &Path {
        Path::new(self)
    }
}

impl AsRef<Path> for Path {
    #[inline]
    fn as_ref(&self) -> &Path {
        self
    }
}
