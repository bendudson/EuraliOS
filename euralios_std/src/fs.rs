//! Filesystem

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;
use core::str;
use core::fmt;
use core::convert::AsRef;
use serde_json::Value;

use crate::{path::{Path, PathBuf, Component},
            println,
            syscalls::{self, CommHandle, SyscallError, MemoryHandle},
            message::{self, rcall, Message, MessageData},
            env};

#[derive(Clone, Debug)]
pub struct OpenOptions {
    write: bool,
    append: bool,
    create: bool,
    truncate: bool
}

impl OpenOptions {
    /// Creates a blank new set of options ready for configuration.
    ///
    /// All options are initially set to `false`.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::fs::OpenOptions;
    ///
    /// let mut options = OpenOptions::new();
    /// let file = options.read(true).open("foo.txt");
    /// ```
    pub fn new() -> OpenOptions {
        OpenOptions{write: false,
                    append: false,
                    create: false,
                    truncate: false}
    }

    /// Sets the option for read access.
    ///
    /// This option, when true, will indicate that the file should be
    /// `read`-able if opened.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::fs::OpenOptions;
    ///
    /// let file = OpenOptions::new().read(true).open("foo.txt");
    /// ```
    pub fn read(&mut self, _read: bool) -> &mut OpenOptions {
        self // Has no effect
    }

    /// Sets the option for write access.
    ///
    /// This option, when true, will indicate that the file should be
    /// `write`-able if opened.
    ///
    /// If the file already exists, any write calls on it will overwrite its
    /// contents, without truncating it.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::fs::OpenOptions;
    ///
    /// let file = OpenOptions::new().write(true).open("foo.txt");
    /// ```
    pub fn write(&mut self, write: bool) -> &mut OpenOptions {
        self.write = write; self
    }

    /// Sets the option for the append mode.
    ///
    /// This option, when true, means that writes will append to a file instead
    /// of overwriting previous contents.
    /// Note that setting `.write(true).append(true)` has the same effect as
    /// setting only `.append(true)`.
    ///
    /// For most filesystems, the operating system guarantees that all writes are
    /// atomic: no writes get mangled because another process writes at the same
    /// time.
    ///
    /// One maybe obvious note when using append-mode: make sure that all data
    /// that belongs together is written to the file in one operation. This
    /// can be done by concatenating strings before passing them to [`write()`],
    /// or using a buffered writer (with a buffer of adequate size),
    /// and calling [`flush()`] when the message is complete.
    ///
    /// If a file is opened with both read and append access, beware that after
    /// opening, and after every write, the position for reading may be set at the
    /// end of the file. So, before writing, save the current position (using
    /// [`seek`]`(`[`SeekFrom`]`::`[`Current`]`(0))`, and restore it before the next read.
    ///
    /// ## Note
    ///
    /// This function doesn't create the file if it doesn't exist. Use the [`create`]
    /// method to do so.
    ///
    /// [`write()`]: ../../std/fs/struct.File.html#method.write
    /// [`flush()`]: ../../std/fs/struct.File.html#method.flush
    /// [`seek`]: ../../std/fs/struct.File.html#method.seek
    /// [`SeekFrom`]: ../../std/io/enum.SeekFrom.html
    /// [`Current`]: ../../std/io/enum.SeekFrom.html#variant.Current
    /// [`create`]: #method.create
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::fs::OpenOptions;
    ///
    /// let file = OpenOptions::new().append(true).open("foo.txt");
    /// ```
    pub fn append(&mut self, append: bool) -> &mut OpenOptions {
        self.append = append; self
    }

    /// Sets the option for truncating a previous file.
    ///
    /// If a file is successfully opened with this option set it will truncate
    /// the file to 0 length if it already exists.
    ///
    /// The file must be opened with write access for truncate to work.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::fs::OpenOptions;
    ///
    /// let file = OpenOptions::new().write(true).truncate(true).open("foo.txt");
    /// ```
    pub fn truncate(&mut self, truncate: bool) -> &mut OpenOptions {
        self.truncate = truncate; self
    }

    /// Sets the option for creating a new file.
    ///
    /// This option indicates whether a new file will be created if the file
    /// does not yet already exist.
    ///
    /// In order for the file to be created, [`write`] or [`append`] access must
    /// be used.
    ///
    /// [`write`]: #method.write
    /// [`append`]: #method.append
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::fs::OpenOptions;
    ///
    /// let file = OpenOptions::new().write(true).create(true).open("foo.txt");
    /// ```
    pub fn create(&mut self, create: bool) -> &mut OpenOptions {
        self.create = create; self
    }

    /// Opens a file at `path` with the options specified by `self`.
    ///
    pub fn open<P: AsRef<Path>>(&self, path: P) -> Result<File, SyscallError> {
        self._open(path.as_ref())
    }

    fn _open(&self, path: &Path) -> Result<File, SyscallError> {
        let flags = message::O_READ +
            if self.write || self.append { message::O_WRITE } else { 0 } +
            if self.create { message::O_CREATE } else { 0 } +
            if self.truncate { message::O_TRUNCATE } else { 0 };

        let pwd_or_err = env::current_dir();
        let handle = if path.is_relative() & pwd_or_err.is_ok() {
            let mut abspath = pwd_or_err.unwrap();
            abspath.push(path);
            syscalls::open(abspath.as_os_str(), flags)?
        } else {
            syscalls::open(path.as_os_str(), flags)?
        };
        Ok(File(handle))
    }
}

/// Represents a file
///
/// Intended to have the same API as `std::file::File`
/// <https://doc.rust-lang.org/std/fs/struct.File.html>
///
/// Wrapper around a CommHandle
#[derive(Debug)]
pub struct File(CommHandle);

/// The result of a File query.
///
/// Wrapper around serde_json::Value, to make changing
/// the internal representation easier in future.
#[derive(Debug)]
pub struct FileQuery(Value);

impl File {
    const MAX_SIZE: u64 = 0xFFFF_FFFF_FFFF_FFFF;

    /// Opens a file in write-only mode.
    ///
    /// This function will create a file if it does not exist, and
    /// will truncate it if it does.
    pub fn create<P: AsRef<Path>>(path: P) -> Result<File, SyscallError> {
        let pwd_or_err = env::current_dir();
        let handle = if path.as_ref().is_relative() & pwd_or_err.is_ok() {
            let mut abspath = pwd_or_err.unwrap();
            abspath.push(path.as_ref());
            syscalls::open(abspath.as_os_str(), message::O_WRITE + message::O_CREATE + message::O_TRUNCATE)?
        } else {
            syscalls::open(path.as_ref().as_os_str(), message::O_WRITE + message::O_CREATE + message::O_TRUNCATE)?
        };
        Ok(File(handle))
    }

    pub fn open<P: AsRef<Path>>(path: P) -> Result<File, SyscallError> {
        let pwd_or_err = env::current_dir();
        let handle = if path.as_ref().is_relative() & pwd_or_err.is_ok() {
            let mut abspath = pwd_or_err.unwrap();
            abspath.push(path.as_ref());
            syscalls::open(abspath.as_os_str(), message::O_READ)?
        } else {
            syscalls::open(path.as_ref().as_os_str(), message::O_READ)?
        };
        Ok(File(handle))
    }

    /// Convert to CommHandle
    ///
    /// EuraliOS only
    pub fn to_CommHandle(self) -> CommHandle {
        self.0
    }

    /// Query a file handle
    ///
    /// EuraliOS only
    pub fn query(&self) -> Result<FileQuery, SyscallError> {
        match rcall(&self.0,
                    message::QUERY,
                    0.into(), 0.into(), None) {
            Ok((message::JSON,
                MessageData::Value(length),
                MessageData::MemoryHandle(handle))) => {

                let u8_slice = handle.as_slice::<u8>(length as usize);
                if let Ok(s) = str::from_utf8(u8_slice) {
                    match serde_json::from_str::<Value>(s) {
                        Ok(v) => Ok(FileQuery(v)),
                        Err(err) => {
                            println!("File::query error {:?} parsing {}",
                                     err, s);
                            Err(syscalls::SYSCALL_ERROR_PARAM)
                        }
                    }
                } else {
                    Err(syscalls::SYSCALL_ERROR_PARAM)
                }
            },
            message => {
                println!("[query] received {:?}", message);
                Err(syscalls::SYSCALL_ERROR_PARAM)
            }
        }
    }

    /// Remote call. Send a message and wait for a reply
    ///
    /// EuraliOS only
    pub fn rcall(
        &self,
        data1: u64,
        data2: MessageData,
        data3: MessageData
    ) -> Result<(u64, MessageData, MessageData),
                (SyscallError, Message)> {
        rcall(&self.0,
              data1, data2, data3,
              None)
    }

    /// Write a buffer into this writer, returning how many bytes were
    /// written.
    ///
    /// Note: This is part of the io::Write trait impl
    pub fn write(&mut self, buf: &[u8]) -> Result<usize, SyscallError> {
        // Copy buffer into pages which can be sent
        match rcall(&self.0,
                    message::WRITE,
                    (buf.len() as u64).into(),
                    MemoryHandle::from_u8_slice(buf).into(),
                    None) {
            Ok((message::OK,
                MessageData::Value(sent_length), _)) => Ok(sent_length as usize),
            Err((err, _message)) => Err(err),
            result => {
                println!("File::write unexpected result {:?}", result);
                Err(syscalls::SYSCALL_ERROR_PARAM)
            }
        }
    }

    /// Read all bytes until EOF in this source, placing them into buf
    pub fn read_to_end(&mut self, buf: &mut Vec<u8>)
                       -> Result<usize, SyscallError> {
        match rcall(&self.0,
                    message::READ, 0.into(), Self::MAX_SIZE.into(),
                    None) {
            Ok((message::DATA, MessageData::Value(length), MessageData::MemoryHandle(data))) => {
                let length = length as usize;
                buf.extend_from_slice(data.as_slice::<u8>(length));
                Ok(length)
            },
            Err((err, _message)) => Err(err),
            result => {
                println!("File::read_to_end unexpected result {:?}", result);
                Err(syscalls::SYSCALL_ERROR_PARAM)
            }
        }
    }
}

/// Metadata information about a file.
#[derive(Clone)]
pub struct Metadata {
    is_dir : bool
}

impl Metadata {
    /// Returns true if this metadata is for a directory. The result
    /// is mutually exclusive to the result of is_file
    pub fn is_dir(&self) -> bool {
        self.is_dir
    }

    /// Returns true if this metadata is for a regular file.
    pub fn is_file(&self) -> bool {
        !self.is_dir
    }
}

impl fmt::Debug for Metadata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Metadata")
            //.field("file_type", &self.file_type())
            .field("is_dir", &self.is_dir())
            .field("is_file", &self.is_file())
            //.field("permissions", &self.permissions())
            //.field("modified", &self.modified())
            //.field("accessed", &self.accessed())
            //.field("created", &self.created())
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub struct DirEntry {
    name: String,
    meta: Metadata
}

impl DirEntry {
    /// Return the bare file name of this directory entry without any
    /// other leading path component.
    pub fn file_name(&self) -> &str {
        &self.name
    }

    /// Returns the metadata for the file that this entry points at.
    pub fn metadata(&self) -> Result<Metadata, SyscallError> {
        Ok(self.meta.clone())
    }
}

/// Iterator yielding Result<DirEntry>
#[derive(Debug)]
pub struct ReadDir {
    entries: Vec<DirEntry>
}

impl Iterator for ReadDir {
    type Item = Result<DirEntry, SyscallError>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(entry) = self.entries.pop() {
            return Some(Ok(entry));
        }
        None
    }
}

pub fn read_dir<P: AsRef<Path>>(
    path: P
) -> Result<ReadDir, SyscallError> {
    let path: &Path = path.as_ref();

    let f = File::open(path)?;
    let query = f.query()?;

    let mut entries = match query.0["files"].as_array() {
        Some(vec) => {
            // Transform into a Vec of DirEntry objects
            vec.iter().map(|obj| DirEntry{
                name: String::from(obj["name"].as_str().unwrap_or("_bad_")),
                meta: Metadata {
                    is_dir: false
                }
            }).collect()
        }
        _ => Vec::new()
    };

    if let Some(vec) = query.0["subdirs"].as_array() {
        // Some directories
        for obj in vec {
            entries.push(DirEntry{
                name: String::from(obj["name"].as_str().unwrap_or("_bad_")),
                meta: Metadata {
                    is_dir: true
                }
            });
        }
    }

    Ok(ReadDir{
        entries
    })
}

/// Delete a file
pub fn remove_file<P: AsRef<Path>>(path: P) -> Result<(), SyscallError> {
    let path: &Path = path.as_ref();

    // Get the directory containing the file
    let parent = match path.parent() {
        Some(parent) => parent,
        None => { return Err(syscalls::SYSCALL_ERROR_PARAM); }
    };

    // Get the file part of the path
    let file_name = match path.file_name() {
        Some(name) => name,
        None => { return Err(syscalls::SYSCALL_ERROR_PARAM); }
    };

    // Open the directory containing this file
    let f = File::open(parent)?;

    // Send a delete message
    let bytes = file_name.bytes();
    match f.rcall(message::DELETE,
                  (bytes.len() as u64).into(),
                  MemoryHandle::from_u8_slice(bytes).into()) {
        Err((err, _)) => Err(err),
        Ok((message::OK, _, _)) => Ok(()),
        _ => Err(syscalls::SYSCALL_ERROR_PARAM)
    }
}

pub fn create_dir<P: AsRef<Path>>(path: P) -> Result<(), SyscallError> {
    let path: &Path = path.as_ref();

    // Get the directory's parent
    let parent = match path.parent() {
        Some(parent) => parent,
        None => { return Err(syscalls::SYSCALL_ERROR_PARAM); }
    };

    // Get the final part of the path
    let new_dir_name = match path.file_name() {
        Some(name) => name,
        None => { return Err(syscalls::SYSCALL_ERROR_PARAM); }
    };

    // Open the parent directory for modifying
    let f = OpenOptions::new().write(true).open(parent)?;

    // Send a MKDIR message
    let bytes = new_dir_name.bytes();
    match f.rcall(message::MKDIR,
                  (bytes.len() as u64).into(),
                  MemoryHandle::from_u8_slice(bytes).into()) {
        Err((err, _)) => Err(err),
        Ok((message::OK, _, _)) => Ok(()),
        _ => Err(syscalls::SYSCALL_ERROR_PARAM)
    }
}

/// Returns the canonical, absolute form of a path with all intermediate
/// components normalized and symbolic links resolved.
pub fn canonicalize<P: AsRef<Path>>(
    path: P
) -> Result<PathBuf, ()> {
    let path: &Path = path.as_ref();

    let mut pathbuf = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir => {
                pathbuf.push("/");
            }
            Component::ParentDir => {
                pathbuf.pop();
            }
            Component::Normal(s) => {
                pathbuf.push(s);
            }
            _ => {}
        }
    }
    return Ok(pathbuf)
}

#[cfg(test)]
pub mod tests {
    use super::canonicalize;
    use crate::path::PathBuf;

    #[test_case]
    fn canonicalize() {
        let path_buf = canonicalize("/a/b/../c/./d").unwrap();
        assert_eq!(path_buf, PathBuf::from("/a/c/d"));
    }
}
