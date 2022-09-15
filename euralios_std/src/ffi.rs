//! OsString and OsStr
//!
//! In EuraliOS these are just wrappers around String and str
//!
//! This code was mostly copied from the Rust standard library
//! <https://doc.rust-lang.org/stable/src/std/path.rs.html>

extern crate alloc;
use alloc::string::String;
use alloc::borrow::ToOwned;
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

    /// Creates a new `OsString` with at least the given capacity.
    ///
    /// The string will be able to hold at least `capacity` length units of other
    /// OS strings without reallocating. This method is allowed to allocate for
    /// more units than `capacity`. If `capacity` is 0, the string will not
    /// allocate.
    ///
    /// See the main `OsString` documentation information about encoding and capacity units.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::ffi::OsString;
    ///
    /// let mut os_string = OsString::with_capacity(10);
    /// let capacity = os_string.capacity();
    ///
    /// // This push is done without reallocating
    /// os_string.push("foo");
    ///
    /// assert_eq!(capacity, os_string.capacity());
    /// ```
    #[must_use]
    #[inline]
    pub fn with_capacity(capacity: usize) -> OsString {
        OsString { inner: String::with_capacity(capacity) }
    }

    /// Extends the string with the given <code>&[OsStr]</code> slice.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::ffi::OsString;
    ///
    /// let mut os_string = OsString::from("foo");
    /// os_string.push("bar");
    /// assert_eq!(&os_string, "foobar");
    /// ```
    #[inline]
    pub fn push<T: AsRef<OsStr>>(&mut self, s: T) {
        self.inner.push_str(&s.as_ref().inner)
    }

    /// Returns the capacity this `OsString` can hold without reallocating.
    ///
    /// See the main `OsString` documentation information about encoding and capacity units.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::ffi::OsString;
    ///
    /// let os_string = OsString::with_capacity(10);
    /// assert!(os_string.capacity() >= 10);
    /// ```
    #[must_use]
    #[inline]
    pub fn capacity(&self) -> usize {
        self.inner.capacity()
    }
}

impl ops::Deref for OsString {
    type Target = OsStr;

    #[inline]
    fn deref(&self) -> &OsStr {
        (&self.inner[..]).as_ref()
    }
}

impl fmt::Debug for OsString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&**self, formatter)
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

impl<T: ?Sized + AsRef<OsStr>> From<&T> for OsString {
    /// Copies any value implementing <code>[AsRef]&lt;[OsStr]&gt;</code>
    /// into a newly allocated [`OsString`].
    fn from(s: &T) -> OsString {
        s.as_ref().to_os_string()
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

    /// Copies the slice into an owned [`OsString`].
    ///
    /// # Examples
    ///
    /// ```
    /// use std::ffi::{OsStr, OsString};
    ///
    /// let os_str = OsStr::new("foo");
    /// let os_string = os_str.to_os_string();
    /// assert_eq!(os_string, OsString::from("foo"));
    /// ```
    #[must_use = "this returns the result of the operation, \
                  without modifying the original"]
    #[inline]
    pub fn to_os_string(&self) -> OsString {
        OsString { inner: self.inner.to_owned() }
    }
}

impl AsRef<OsStr> for OsStr {
    #[inline]
    fn as_ref(&self) -> &OsStr {
        self
    }
}

impl AsRef<OsStr> for OsString {
    #[inline]
    fn as_ref(&self) -> &OsStr {
        self
    }
}

impl AsRef<OsStr> for str {
    #[inline]
    fn as_ref(&self) -> &OsStr {
        // OsStr and str have the same representation
        unsafe{ &*(self as *const str as *const OsStr) }
    }
}

impl AsRef<OsStr> for String {
    #[inline]
    fn as_ref(&self) -> &OsStr {
        (&**self).as_ref()
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
    use super::{OsString, OsStr};

    #[test_case]
    fn OsStr_to_str() {
        let os_str = OsStr::new("foo");
        assert_eq!(os_str.to_str(), Some("foo"));
    }

    #[test_case]
    fn OsStr_to_os_string() {
        let os_str = OsStr::new("foo");
        let os_string = os_str.to_os_string();
        assert_eq!(os_string, OsString::from("foo"));
    }

    #[test_case]
    fn OsString_with_capacity() {
        let mut os_string = OsString::with_capacity(10);
        let capacity = os_string.capacity();

        // This push is done without reallocating
        os_string.push("foo");
        assert_eq!(capacity, os_string.capacity());
    }

    #[test_case]
    fn OsString_push() {
        let mut os_string = OsString::from("foo");
        os_string.push("bar");
        assert_eq!(&os_string, "foobar");
    }

    #[test_case]
    fn OsString_capacity() {
        let os_string = OsString::with_capacity(10);
        assert!(os_string.capacity() >= 10);
    }
}

