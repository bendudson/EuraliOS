#![no_std]
#![no_main]

extern crate alloc;
use alloc::collections::btree_map::BTreeMap;
use alloc::string::String;
use alloc::format;
use core::str;

use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::RwLock;

use euralios_std::{println,
                   thread,
                   path::Path,
                   message::{self, Message, MessageData},
                   syscalls::{self, STDIN, CommHandle},
                   sys::path::MAIN_SEP_STR};

/// Represents a file as a bag of bytes
struct File {
    data: Vec<u8>
}

impl File {
    fn new() -> Self {
        File{data: Vec::new()}
    }

    fn clear(&mut self) {
        self.data.clear();
    }
}

/// A tree structure of directories containing File objects
///
/// All subdirectories and files are wrapped in Arc<RwLock<>> because:
/// - Multiple processes may hold handles to the same directory or
///   file
/// - Hard links where multiple files point to the same data
struct Directory {
    subdirs: BTreeMap<String, Arc<RwLock<Directory>>>,
    files: BTreeMap<String, Arc<RwLock<File>>>
}


/// Open a file or directory
///
/// This will create files but not directories
fn open(mut dir: Arc<RwLock<Directory>>, path: &Path, flags: u64) -> Result<CommHandle, ()> {
    println!("[ramdisk] Opening {:?}", path);

    let mut path_iter = path.iter().peekable();
    while let Some(component) = path_iter.next()  {
        // Convert to a string for indexing
        let key = component.to_str().unwrap();

        if dir.read().subdirs.contains_key(key) {
            if path_iter.peek().is_none() {
                // No further path components => Opening an existing directory
                let readwrite = (flags & message::O_WRITE) == message::O_WRITE;
                println!("Starting handle_directory({}, rw:{})", key, readwrite);

                // Make a new communication handle pair
                let (handle, client_handle) = syscalls::new_rendezvous()
                    .map_err(|e| {println!("[ramdisk] Couldn't create Rendezvous {:?}", e);})?;

                let subdir = dir.read().subdirs[key].clone();

                // Start a thread
                thread::spawn(move || {
                    handle_directory(subdir, handle, readwrite);
                });

                // Return the other handle to the client
                return Ok(client_handle)
            } else {
                // Further components => Move to subdirectory
                let subdir = dir.read().subdirs[key].clone();
                dir = subdir;
            }
        } else if dir.read().files.contains_key(key) {
            if path_iter.peek().is_some() {
                println!("[ramdisk] Error opening path {:?}: {} is a file not a directory", path, key);
                return Err(());
            }

            // No more components -> Opening an existing file
            let file = dir.read().files[key].clone();

            if (flags & message::O_TRUNCATE) == message::O_TRUNCATE {
                // Delete contents
                file.write().clear();
            }

            // Make a new communication handle pair
            let (handle, client_handle) = syscalls::new_rendezvous()
                .map_err(|e| {println!("[ramdisk] Couldn't create Rendezvous {:?}", e);})?;

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
            println!("[ramdisk] Error opening path {:?}: {} not found", path, key);
            return Err(());
        } else if (flags & message::O_CREATE) == message::O_CREATE {
            // Create a file

            let new_file = Arc::new(RwLock::new(File::new()));
            dir.write().files.insert(String::from(key), new_file.clone());

            let (handle, client_handle) = syscalls::new_rendezvous()
                .map_err(|e| {println!("[ramdisk] Couldn't create Rendezvous {:?}", e);})?;

            thread::spawn(move || {
                handle_file_readwrite(new_file, handle);
            });

            return Ok(client_handle);
        } else {
            // Missing a file
            println!("[ramdisk] Error opening path {:?}: {} not found", path, key);
            return Err(());
        }
    }
    Err(())
}

impl Directory {
    fn new() -> Self {
        Directory {
            subdirs: BTreeMap::new(),
            files: BTreeMap::new()
        }
    }

    /// Delete a file
    fn delete(&mut self, path: &str) -> Result<(), ()> {
        let path = path.trim_start_matches('/');
        println!("[ramdisk] Deleting {}", path);

        if self.files.contains_key(path) {
            self.files.remove(path);
            Ok(())
        } else {
            Err(())
        }
    }

    /// Make a sub-directory
    fn mkdir (&mut self, path: &str) -> Result<(), syscalls::SyscallError> {
        println!("[ramdisk] Making directory {}", path);
        if path.contains(MAIN_SEP_STR) {
            // Cannot contain separator
            return Err(syscalls::SYSCALL_ERROR_PARAM);
        }
        if self.subdirs.contains_key(path) {
            // Already exists
            return Err(syscalls::SYSCALL_ERROR_EXISTS);
        }
        let new_dir = Arc::new(RwLock::new(Directory::new()));
        self.subdirs.insert(String::from(path), new_dir);
        Ok(())
    }
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
fn handle_file_readwrite(file: Arc<RwLock<File>>,
                         comm_handle: CommHandle) {
    dispatch_loop(
        &comm_handle,
        |msg| {
            match msg {
                syscalls::Message::Long(
                    message::WRITE,
                    MessageData::Value(length),
                    MessageData::MemoryHandle(handle)) => {

                    let u8_slice = handle.as_slice::<u8>(length as usize);

                    println!("[ramdisk] Writing {} bytes", length);

                    // Append data to file
                    file.write().data.extend_from_slice(u8_slice);

                    // Return success
                    syscalls::send(&comm_handle,
                                   syscalls::Message::Short(
                                       message::OK, length, 0));
                },
                syscalls::Message::Short(
                    message::READ, start, length) => {

                    let f = file.read();

                    if f.data.len() == 0 {
                        // No data
                        syscalls::send(&comm_handle,
                                       syscalls::Message::Short(
                                           message::ERROR, 0, 0));
                    } else {
                        syscalls::send(&comm_handle,
                                       syscalls::Message::Long(
                                           message::DATA,
                                           (f.data.len() as u64).into(),
                                           syscalls::MemoryHandle::from_u8_slice(&f.data).into()));
                    }
                }
                msg => {
                    println!("[ramdisk handle_file] -> {:?}", msg);
                }
            }
        });
}

/// Serve messages received from a communication channel
/// Only allow reading from the file
fn handle_file_readonly(file: Arc<RwLock<File>>,
                        comm_handle: CommHandle) {
    dispatch_loop(
        &comm_handle,
        |msg| {
            match msg {
                syscalls::Message::Short(
                    message::READ, start, length) => {

                    let f = file.read();

                    if f.data.len() == 0 {
                        // No data
                        syscalls::send(&comm_handle,
                                       syscalls::Message::Short(
                                           message::ERROR, 0, 0));
                    } else {
                        syscalls::send(&comm_handle,
                                       syscalls::Message::Long(
                                           message::DATA,
                                           (f.data.len() as u64).into(),
                                           syscalls::MemoryHandle::from_u8_slice(&f.data).into()));
                    }
                }
                msg => {
                    println!("[ramdisk handle_file] -> {:?}", msg);
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
fn handle_directory(directory: Arc<RwLock<Directory>>,
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
                        if directory.write().delete(path).is_ok() {
                            syscalls::send(&comm_handle,
                                           syscalls::Message::Short(
                                               message::OK, 0, 0));
                        } else {
                            syscalls::send(&comm_handle,
                                           syscalls::Message::Short(
                                               message::ERROR_INVALID_VALUE, 0, 0));
                        }
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
                        if let Err(_err) = directory.write().mkdir(path) {
                            syscalls::send(&comm_handle,
                                           syscalls::Message::Short(
                                               message::ERROR_INVALID_VALUE, 0, 0));
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
                            Err(_err) => {
                                // Error opening path
                                syscalls::send(&comm_handle,
                                               syscalls::Message::Short(
                                                   message::ERROR_INVALID_VALUE, 0, 0));
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

                    let dir = directory.read();

                    // Make a list of files
                    let file_list = {
                        let mut s = String::new();
                        let mut it = dir.files.keys().peekable();
                        while let Some(name) = it.next() {
                            s.reserve(name.len() + 13);
                            s.push_str("{\"name\":\"");
                            s.push_str(name);
                            s.push_str("\"}");
                            if it.peek().is_some() {
                                s.push_str(", ");
                            }
                        }
                        s
                    };

                    // Make a list of directories
                    let subdir_list = {
                        let mut s = String::new();
                        let mut it = dir.subdirs.keys().peekable();
                        while let Some(name) = it.next() {
                            s.reserve(name.len() + 13);
                            s.push_str("{\"name\":\"");
                            s.push_str(name);
                            s.push_str("\"}");
                            if it.peek().is_some() {
                                s.push_str(", ");
                            }
                        }
                        s
                    };

                    let info = format!("{{
\"short\": \"Ramdisk directory\",
\"messages\": [{{\"name\": \"open\",
                 \"tag\": {open_tag}}},
               {{\"name\": \"query\",
                 \"tag\": {query_tag}}}],
\"readwrite\": {readwrite},
\"subdirs\": [{subdir_list}],
\"files\": [{file_list}]}}",
                                       open_tag = message::OPEN,
                                       query_tag = message::QUERY,
                                       readwrite = readwrite,
                                       file_list = file_list,
                                       subdir_list = subdir_list);

                    // Copy and send as memory handle
                    let mem_handle = syscalls::MemoryHandle::from_u8_slice(&info.as_bytes());
                    syscalls::send(&comm_handle,
                                   syscalls::Message::Long(
                                       message::JSON,
                                       (info.len() as u64).into(),
                                       mem_handle.into()));
                },
                message => {
                    println!("[ramdisk] Received unexpected message {:?}", message);
                }
            }
        });
}

#[no_mangle]
fn main() {
    println!("[ramdisk] Starting ramdisk");

    let fs = Directory::new();

    handle_directory(Arc::new(RwLock::new(fs)), STDIN.clone(), true);
}
