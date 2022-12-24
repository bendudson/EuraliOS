//! EuraliOS-specific functions for servers
//!
//! Dispatches messages to interact with file-like and directory-like
//! objects.

extern crate alloc;
use alloc::{string::String, sync::Arc};
use spin::RwLock;
use core::str;

use crate::{path::Path,
            println,
            thread,
            message::{self, Message, MessageData},
            syscalls::{self, CommHandle, malloc}};

pub trait FileLike {
    /// Number of bytes in the file
    fn len(&self) -> usize;
    /// Read data starting at a given offset, storing in pre-allocated slice
    fn read(&self, _start: usize, _buffer: &mut [u8]) -> Result<usize, syscalls::SyscallError> {
        Err(syscalls::SYSCALL_ERROR_NOT_IMPLEMENTED)
    }
    /// Write data starting at given offset
    fn write(&mut self, _start: usize, _buffer: &[u8]) -> Result<usize, syscalls::SyscallError> {
        Err(syscalls::SYSCALL_ERROR_NOT_IMPLEMENTED)
    }
    /// Delete contents
    fn clear(&mut self) -> Result<(), syscalls::SyscallError> {
        Err(syscalls::SYSCALL_ERROR_NOT_IMPLEMENTED)
    }
}

pub trait DirLike {
    /// Lookup and return shared reference to a directory
    fn get_dir(&self, name: &str) -> Result<Arc<RwLock<dyn DirLike + Sync + Send>>, syscalls::SyscallError>;
    /// Lookup and return shared reference to a file
    fn get_file(&self, name: &str) -> Result<Arc<RwLock<dyn FileLike + Sync + Send>>, syscalls::SyscallError>;
    /// Return a JSON string describing the directory and its contents
    fn query(&self) -> String;

    /// Create a new subdirectory, returning a shared reference
    fn make_dir(&mut self, _name: &str) -> Result<Arc<RwLock<dyn DirLike + Sync + Send>>, syscalls::SyscallError> {
        Err(syscalls::SYSCALL_ERROR_NOT_IMPLEMENTED)
    }

    /// Create a new file, returning a shared reference
    fn make_file(&mut self, _name: &str) -> Result<Arc<RwLock<dyn FileLike + Sync + Send>>, syscalls::SyscallError> {
        Err(syscalls::SYSCALL_ERROR_NOT_IMPLEMENTED)
    }
    /// Lookup and remove subdirectory, returning the shared reference
    fn remove_dir(&mut self, _name: &str) -> Result<Arc<RwLock<dyn DirLike + Sync + Send>>, syscalls::SyscallError> {
        Err(syscalls::SYSCALL_ERROR_NOT_IMPLEMENTED)
    }
    /// Lookup and remove file, returning the shared reference
    fn remove_file(&mut self, _name: &str) -> Result<Arc<RwLock<dyn FileLike + Sync + Send>>, syscalls::SyscallError> {
        Err(syscalls::SYSCALL_ERROR_NOT_IMPLEMENTED)
    }
}

/// Open a file or directory
///
/// This will create files but not directories
fn open(mut dir: Arc<RwLock<dyn DirLike + Sync + Send>>, path: &Path, flags: u64) -> Result<CommHandle, syscalls::SyscallError> {
    println!("Opening {:?}", path);

    let mut path_iter = path.iter().peekable();
    while let Some(component) = path_iter.next()  {
        // Convert to a string for indexing
        let key = component.to_str().unwrap();

        let result_subdir = dir.read().get_dir(key);
        if let Ok(subdir) = result_subdir {
            if path_iter.peek().is_none() {
                // No further path components => Opening an existing directory
                let readwrite = (flags & message::O_WRITE) == message::O_WRITE;
                println!("Starting handle_directory({}, rw:{})", key, readwrite);

                // Make a new communication handle pair
                let (handle, client_handle) = syscalls::new_rendezvous()?;

                // Start a thread
                thread::spawn(move || {
                    handle_directory(subdir, handle, readwrite);
                });

                // Return the other handle to the client
                return Ok(client_handle)
            } else {
                // Further components => Move to subdirectory
                dir = subdir;
            }
        } else {
            let result_file = dir.read().get_file(key);
            if let Ok(file) = result_file {
                if path_iter.peek().is_some() {
                    println!("Error opening path {:?}: {} is a file not a directory", path, key);
                    return Err(syscalls::SYSCALL_ERROR_NOT_DIR);
                }
                // No more components -> Opening an existing file

                if (flags & message::O_TRUNCATE) == message::O_TRUNCATE {
                    // Delete contents
                    file.write().clear();
                }

                // Make a new communication handle pair
                let (handle, client_handle) = syscalls::new_rendezvous()?;

                // Start a thread
                if (flags & message::O_WRITE) == message::O_WRITE {
                    thread::spawn(move || {
                        handle_file_readwrite(file, handle);
                    });
                } else {
                    thread::spawn(move || {
                        handle_file_readonly(file, handle);
                    });
                }

                // Return the other handle to the client
                return Ok(client_handle);
            } else if path_iter.peek().is_some() {
                // Missing a directory
                println!("Error opening path {:?}: {} not found", path, key);
                return Err(syscalls::SYSCALL_ERROR_NOTFOUND);
            } else if (flags & message::O_CREATE) == message::O_CREATE {
                // Create a file

                let new_file = dir.write().make_file(key)?;
                let (handle, client_handle) = syscalls::new_rendezvous()?;

                thread::spawn(move || {
                    handle_file_readwrite(new_file, handle);
                });

                return Ok(client_handle);
            } else {
                // Missing a file
                println!("Error opening path {:?}: {} not found", path, key);
                return Err(syscalls::SYSCALL_ERROR_NOTFOUND);
            }
        }
    }
    Err(syscalls::SYSCALL_ERROR_NOTFOUND)
}

/// Dispatch messages in a loop, returning when the communication handle
/// is closed. This function handles common error messages, passing
/// other messages to the given function `f`.
///
fn dispatch_loop<F>(handle: &CommHandle,
                    mut f: F)
where
    F: FnMut(syscalls::Message) -> (),
{
    loop {
        match syscalls::receive(handle) {
            Ok(syscalls::Message::Short(
                message::CLOSE, _, _)) => {
                // Close this file handler, dropping comm_handle
                return;
            },
            Err(syscalls::SYSCALL_ERROR_RECV_BLOCKING) => {
                // Waiting for a message
                // => Send an error message
                syscalls::send(handle,
                               syscalls::Message::Short(
                                   message::ERROR, 0, 0));
                // Wait and try again
                syscalls::thread_yield();
            },
            Err(syscalls::SYSCALL_ERROR_CLOSED) => {
                // Other Rendezvous handles have been dropped
                return;
            },
            Ok(msg) => f(msg),
            Err(code) => {
                println!("[ramdisk] Receive error {}", code);
                // Wait and try again
                syscalls::thread_yield();
            }
        }
    }
}

/// Serve messages received from a communication channel
/// reading and writing data from a file
fn handle_file_readwrite(file: Arc<RwLock<dyn FileLike + Sync + Send>>,
                         comm_handle: CommHandle) {
    dispatch_loop(
        &comm_handle,
        |msg| {
            match msg {
                syscalls::Message::Long(
                    message::WRITE,
                    MessageData::Value(length),
                    MessageData::MemoryHandle(handle)) => {

                    // Append data to file
                    match file.write().write(0, handle.as_slice::<u8>(length as usize)) {
                        Ok(written) => {
                            // Return success
                            syscalls::send(&comm_handle,
                                           syscalls::Message::Short(
                                               message::OK, written as u64, 0));
                        },
                        Err(sys_err) => {
                            // Return error
                            syscalls::send(&comm_handle,
                                           syscalls::Message::Short(
                                               message::ERROR, sys_err.as_u64(), 0));
                        }
                    }
                },
                syscalls::Message::Short(
                    message::READ, start, length) => {

                    let f = file.read();
                    let len = f.len();

                    if len == 0 {
                        // No data
                        syscalls::send(&comm_handle,
                                       syscalls::Message::Short(
                                           message::ERROR,
                                           syscalls::SYSCALL_ERROR_NO_DATA.as_u64(), 0));
                    } else {
                        // Allocate memory
                        let (mut mem_handle, _) = malloc(len as u64, 0).unwrap();
                        // Read data
                        match f.read(start as usize, mem_handle.as_mut_slice(len)) {
                            Ok(nbytes) => syscalls::send(&comm_handle,
                                                         syscalls::Message::Long(
                                                             message::DATA,
                                                             (nbytes as u64).into(),
                                                             mem_handle.into())),
                            Err(sys_err) => syscalls::send(&comm_handle,
                                                           syscalls::Message::Short(
                                                               message::ERROR, sys_err.as_u64(), 0))
                        };
                    }
                },
                msg => {
                    println!("[handle_file] -> {:?}", msg);
                }
            }
        });
}

/// Serve messages received from a communication channel
/// Only allow reading from the file
fn handle_file_readonly(file: Arc<RwLock<dyn FileLike + Sync + Send>>,
                        comm_handle: CommHandle) {
    dispatch_loop(
        &comm_handle,
        |msg| {
            match msg {
                syscalls::Message::Short(
                    message::READ, start, length) => {

                    let f = file.read();
                    let len = f.len();

                    if len == 0 {
                        // No data
                        syscalls::send(&comm_handle,
                                       syscalls::Message::Short(
                                           message::ERROR,
                                           syscalls::SYSCALL_ERROR_NO_DATA.as_u64(), 0));
                    } else {
                        // Allocate memory
                        let (mut mem_handle, _) = malloc(len as u64, 0).unwrap();
                        // Read data
                        match f.read(0, mem_handle.as_mut_slice(len)) {
                            Ok(nbytes) => syscalls::send(&comm_handle,
                                                         syscalls::Message::Long(
                                                             message::DATA,
                                                             (nbytes as u64).into(),
                                                             mem_handle.into())),
                            Err(sys_err) => syscalls::send(&comm_handle,
                                                           syscalls::Message::Short(
                                                               message::ERROR, sys_err.as_u64(), 0))
                        };
                    }
                }
                msg => {
                    println!("[handle_file_readonly] -> {:?}", msg);
                }
            }
        });
}

/// Handle messages for a given directory
///
/// # Arguments
///
/// * `directory` - The directory being viewed or modified
/// * `comm_handle` - Waits for messages on this CommHandle
/// * `readwrite` - If true, allow modifications
///
pub fn handle_directory(directory: Arc<RwLock<dyn DirLike + Sync + Send>>,
                    comm_handle: CommHandle,
                    readwrite: bool) {
    dispatch_loop(
        &comm_handle,
        |msg| {
            match msg {
                Message::Long(
                    message::DELETE,
                    MessageData::Value(length),
                    MessageData::MemoryHandle(handle)) => {
                    // Delete a file

                    if !readwrite {
                        // Error! Read-only
                        syscalls::send(&comm_handle,
                                       syscalls::Message::Short(
                                           message::ERROR_DENIED, 0, 0));
                        return;
                    }

                    // Get the path string
                    let u8_slice = handle.as_slice::<u8>(length as usize);
                    if let Ok(path) = str::from_utf8(u8_slice) {
                        match directory.write().remove_file(path) {
                            Ok(_) => syscalls::send(&comm_handle,
                                           syscalls::Message::Short(
                                               message::OK, 0, 0)),
                            Err(sys_err) => 
                                syscalls::send(&comm_handle,
                                               syscalls::Message::Short(
                                                   message::ERROR, sys_err.as_u64(), 0))
                        };
                    } else {
                        // UTF-8 error
                        syscalls::send(&comm_handle,
                                       syscalls::Message::Short(
                                       message::ERROR_INVALID_UTF8, 0, 0));
                    }
                }
                Message::Long(
                    message::MKDIR,
                    MessageData::Value(length),
                    MessageData::MemoryHandle(handle)) => {
                    // Make a directory

                    if !readwrite {
                        // Error! Read-only
                        syscalls::send(&comm_handle,
                                       syscalls::Message::Short(
                                           message::ERROR_DENIED, 0, 0));
                        return;
                    }

                    // Get the path string
                    let u8_slice = handle.as_slice::<u8>(length as usize);
                    if let Ok(path) = str::from_utf8(u8_slice) {
                        if let Err(sys_err) = directory.write().make_dir(path) {
                            syscalls::send(&comm_handle,
                                           syscalls::Message::Short(
                                               message::ERROR, sys_err.as_u64(), 0));
                        } else {
                            syscalls::send(&comm_handle,
                                           syscalls::Message::Short(
                                               message::OK, 0, 0));
                        }
                    } else {
                        // UTF-8 error
                        syscalls::send(&comm_handle,
                                       syscalls::Message::Short(
                                       message::ERROR_INVALID_UTF8, 0, 0));
                    }
                }
                Message::Long(
                    tag,
                    MessageData::Value(length),
                    MessageData::MemoryHandle(handle)) if (tag & message::OPEN != 0) => {
                    // Flags for write, create, truncate
                    let flags = tag & message::OPEN_FLAGS_MASK;

                    // Get the path string and try to open it
                    let u8_slice = handle.as_slice::<u8>(length as usize);
                    if let Ok(path) = str::from_utf8(u8_slice) {
                        let path = path.trim_start_matches('/');
                        let result = if flags == message::O_READ {
                            // Read-only
                            open(directory.clone(), Path::new(path), message::O_READ)
                        } else if readwrite {
                            // Write, truncate or create
                            open(directory.clone(), Path::new(path), flags)
                        } else {
                            // Permission denied
                            syscalls::send(&comm_handle,
                                           syscalls::Message::Short(
                                           message::ERROR_DENIED, 0, 0));
                            return;
                        };
                        match result {
                            Ok(handle) => {
                                // Success! Return handle
                                syscalls::send(&comm_handle,
                                               syscalls::Message::Long(
                                                   message::COMM_HANDLE,
                                                   handle.into(), 0.into()));
                            },
                            Err(sys_err) => {
                                // Error opening path
                                syscalls::send(&comm_handle,
                                               syscalls::Message::Short(
                                                   message::ERROR, sys_err.as_u64(), 0));
                            }
                        }
                    } else {
                        // UTF-8 error
                        syscalls::send(&comm_handle,
                                       syscalls::Message::Short(
                                       message::ERROR_INVALID_UTF8, 0, 0));
                    }
                }
                Message::Short(
                    message::QUERY, _, _) => {
                    // Return information about this handle in JSON format
                    let info = directory.read().query();

                    // Copy and send as memory handle
                    let mem_handle = syscalls::MemoryHandle::from_u8_slice(&info.as_bytes());
                    syscalls::send(&comm_handle,
                                   syscalls::Message::Long(
                                       message::JSON,
                                       (info.len() as u64).into(),
                                       mem_handle.into()));
                },
                message => {
                    println!("[handle_directory] Received unexpected message {:?}", message);
                }
            }
        });
}
