//! OsString and OsStr
//!
//! In EuraliOS these are just wrappers around String and str
//!
//! This code was mostly copied from the Rust standard library
//! <https://doc.rust-lang.org/stable/src/std/path.rs.html>

extern crate alloc;
use alloc::string::String;
use core::ops;
use core::cmp;
use core::hash::{Hash, Hasher};
use core::fmt;

pub struct OsString {
    inner: String,
}

/// Borrowed reference to an OS string (see [`OsString`]).
///
/// This type represents a borrowed reference to a string in the operating system's preferred
/// representation.
///
/// `&OsStr` is to [`OsString`] as <code>&[str]</code> is to [`String`]: the
/// former in each pair are borrowed references; the latter are owned strings.
pub struct OsStr {
    inner: str
}

impl OsString {
    /// Constructs a new empty `OsString`.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::ffi::OsString;
    ///
    /// let os_string = OsString::new();
    /// ```
    #[must_use]
    #[inline]
    pub fn new() -> OsString {
        OsString { inner: String::new() }
    }
}

impl ops::Deref for OsString {
    type Target = OsStr;

    #[inline]
    fn deref(&self) -> &OsStr {
        (&self.inner[..]).as_ref()
    }
}

impl PartialEq for OsString {
    #[inline]
    fn eq(&self, other: &OsString) -> bool {
        &**self == &**other
    }
}

impl PartialEq<str> for OsString {
    #[inline]
    fn eq(&self, other: &str) -> bool {
        &**self == other
    }
}

impl OsStr {
    /// Coerces into an `OsStr` slice.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::ffi::OsStr;
    ///
    /// let os_str = OsStr::new("foo");
    /// ```
    #[inline]
    pub fn new<S: AsRef<OsStr> + ?Sized>(s: &S) -> &OsStr {
        s.as_ref()
    }

    /// Yields a <code>&[str]</code> slice if the `OsStr` is valid Unicode.
    ///
    /// This conversion may entail doing a check for UTF-8 validity.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::ffi::OsStr;
    ///
    /// let os_str = OsStr::new("foo");
    /// assert_eq!(os_str.to_str(), Some("foo"));
    /// ```
    #[must_use = "this returns the result of the operation, \
                  without modifying the original"]
    #[inline]
    pub fn to_str(&self) -> Option<&str> {
        Some(&self.inner)
    }

    /// Gets the underlying byte representation.
    ///
    /// Note: it is *crucial* that this API is not externally public, to avoid
    /// revealing the internal, platform-specific encodings.
    #[inline]
    pub fn bytes(&self) -> &[u8] {
        self.inner.as_bytes()
    }
}

impl AsRef<OsStr> for OsStr {
    #[inline]
    fn as_ref(&self) -> &OsStr {
        self
    }
}

// impl AsRef<OsStr> for OsString {
//     #[inline]
//     fn as_ref(&self) -> &OsStr {
//         self
//     }
// }

impl AsRef<OsStr> for str {
    #[inline]
    fn as_ref(&self) -> &OsStr {
        // OsStr and str have the same representation
        unsafe{ &*(self as *const str as *const OsStr) }
    }
}

impl AsRef<str> for OsStr {
    #[inline]
    fn as_ref(&self) -> &str {
        // OsStr and str have the same representation
        unsafe{ &*(self as *const OsStr as *const str) }
    }
}

impl Eq for OsStr {}

impl PartialEq for OsStr {
    #[inline]
    fn eq(&self, other: &OsStr) -> bool {
        self.bytes().eq(other.bytes())
    }
}

impl PartialEq<str> for OsStr {
    #[inline]
    fn eq(&self, other: &str) -> bool {
        *self == *OsStr::new(other)
    }
}

impl PartialOrd for OsStr {
    #[inline]
    fn partial_cmp(&self, other: &OsStr) -> Option<cmp::Ordering> {
        self.bytes().partial_cmp(other.bytes())
    }
    #[inline]
    fn lt(&self, other: &OsStr) -> bool {
        self.bytes().lt(other.bytes())
    }
    #[inline]
    fn le(&self, other: &OsStr) -> bool {
        self.bytes().le(other.bytes())
    }
    #[inline]
    fn gt(&self, other: &OsStr) -> bool {
        self.bytes().gt(other.bytes())
    }
    #[inline]
    fn ge(&self, other: &OsStr) -> bool {
        self.bytes().ge(other.bytes())
    }
}

impl Ord for OsStr {
    #[inline]
    fn cmp(&self, other: &OsStr) -> cmp::Ordering {
        self.bytes().cmp(other.bytes())
    }
}

impl Hash for OsStr {
    #[inline]
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.bytes().hash(state)
    }
}

impl fmt::Debug for OsStr {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.inner, formatter)
    }
}

#[cfg(test)]
pub mod tests {
    use super::OsStr;

    #[test_case]
    fn OsStr_to_str() {
        let os_str = OsStr::new("foo");
        assert_eq!(os_str.to_str(), Some("foo"));
    }
}

