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

impl Directory {
    fn new() -> Self {
        Directory {
            subdirs: BTreeMap::new(),
            files: BTreeMap::new()
        }
    }

    /// Open for reading
    fn openr(&self, path: &str) -> Result<CommHandle, ()> {
        // Strip leading "/"
        let path = path.trim_start_matches('/');
        println!("[ramdisk] Opening {}", path);

        let file = if self.files.contains_key(path) {
            self.files[path].clone()
        } else {
            return Err(());
        };

        // Make a new communication handle pair
        let (handle, client_handle) = syscalls::new_rendezvous()
            .map_err(|e| {println!("[ramdisk] Couldn't create Rendezvous {:?}", e);})?;

        // Start a thread
        thread::spawn(move || {
            handle_file_readonly(file, handle);
        });

        // Return the other handle to the client
        Ok(client_handle)
    }

    /// Open for writing
    fn openw(&mut self, path: &str, flags: u64) -> Result<CommHandle, ()> {
        // Strip leading "/"
        let path = path.trim_start_matches('/');
        println!("[ramdisk] Opening {}", path);

        let file = if self.files.contains_key(path) {
            self.files[path].clone()
        } else if flags & message::O_CREATE != 0 {
            // Create a new file
            let new_file = Arc::new(RwLock::new(File::new()));
            self.files.insert(String::from(path), new_file.clone());
            new_file
        } else {
            return Err(());
        };

        if flags & message::O_TRUNCATE != 0 {
            // Delete contents
            file.write().clear();
        }

        // Make a new communication handle pair
        let (handle, client_handle) = syscalls::new_rendezvous()
            .map_err(|e| {println!("[ramdisk] Couldn't create Rendezvous {:?}", e);})?;

        // Start a thread
        thread::spawn(move || {
            handle_file_readwrite(file, handle);
        });

        // Return the other handle to the client
        Ok(client_handle)
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

fn handle_directory(directory: Arc<RwLock<Directory>>,
                    comm_handle: CommHandle) {
    dispatch_loop(
        &comm_handle,
        |msg| {
            match msg {
                Message::Long(
                    message::DELETE,
                    MessageData::Value(length),
                    MessageData::MemoryHandle(handle)) => {
                    // Delete a file

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
                    tag,
                    MessageData::Value(length),
                    MessageData::MemoryHandle(handle)) if (tag & message::OPEN != 0) => {
                    // Flags for write, create, truncate
                    let flags = tag & message::OPEN_FLAGS_MASK;

                    // Get the path string and try to open it
                    let u8_slice = handle.as_slice::<u8>(length as usize);
                    if let Ok(path) = str::from_utf8(u8_slice) {
                        let result = if flags == message::O_READ {
                            // Read-only
                            directory.read().openr(path)
                        } else {
                            // Write and/or create
                            directory.write().openw(path, flags)
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

                    let info = format!("{{
\"short\": \"Ramdisk directory\",
\"messages\": [{{\"name\": \"open\",
                 \"tag\": {open_tag}}},
               {{\"name\": \"query\",
                 \"tag\": {query_tag}}}],
\"subdirs\": [],
\"files\": [{file_list}]}}",
                                       open_tag = message::OPEN,
                                       query_tag = message::QUERY,
                                       file_list = file_list);

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

    let mut fs = Directory::new();

    handle_directory(Arc::new(RwLock::new(fs)), STDIN.clone());
}
