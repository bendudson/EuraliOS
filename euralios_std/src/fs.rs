//! Filesystem

extern crate alloc;
use alloc::vec::Vec;

use crate::{println,
            syscalls::{self, CommHandle, SyscallError, MemoryHandle},
            message::{self, rcall, MessageData}};

/// Represents a file
///
/// Intended to have the same API as `std::file::File`
/// <https://doc.rust-lang.org/std/fs/struct.File.html>
///
/// Wrapper around a CommHandle
#[derive(Debug)]
pub struct File(CommHandle);

impl File {
    /// Opens a file in write-only mode.
    ///
    /// This function will create a file if it does not exist, and
    /// will truncate it if it does.
    pub fn create(path: &str) -> Result<File, SyscallError> {
        let handle = syscalls::open(path)?;
        Ok(File(handle))
    }

    pub fn open(path: &str) -> Result<File, SyscallError> {
        let handle = syscalls::open(path)?;
        Ok(File(handle))
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
            Err((err, message)) => Err(err),
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
            Err((err, message)) => Err(err),
            result => {
                println!("File::read_to_end unexpected result {:?}", result);
                Err(syscalls::SYSCALL_ERROR_PARAM)
            }
        }
    }
}
