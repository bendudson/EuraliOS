//! Filesystem

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;
use core::str;
use core::fmt;
use core::convert::AsRef;
use serde_json::Value;

use crate::{path::Path,
            println,
            syscalls::{self, CommHandle, SyscallError, MemoryHandle},
            message::{self, rcall, Message, MessageData}};

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
    /// Opens a file in write-only mode.
    ///
    /// This function will create a file if it does not exist, and
    /// will truncate it if it does.
    pub fn create<P: AsRef<Path>>(path: P) -> Result<File, SyscallError> {
        let handle = syscalls::open(path.as_ref().as_os_str(), message::O_WRITE + message::O_CREATE + message::O_TRUNCATE)?;
        Ok(File(handle))
    }

    pub fn open<P: AsRef<Path>>(path: P) -> Result<File, SyscallError> {
        let handle = syscalls::open(path.as_ref().as_os_str(), message::O_READ)?;
        Ok(File(handle))
    }

    /// Query a file handle
    ///
    /// EuraliOS specific
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
                    message::READ, 0.into(), 0.into(),
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
    println!("create_dir: {:?}", path);

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

    // Open the parent directory
    let f = File::open(parent)?;

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
