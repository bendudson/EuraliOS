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
                   syscalls::{self, STDIN, CommHandle}};

/// Represents a file as a bag of bytes
struct File {
    data: Vec<u8>
}

impl File {
    fn new() -> Self {
        File{data: Vec::new()}
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

    fn open(&mut self, path: &str) -> Result<CommHandle, ()> {
        // Strip leading "/"
        let path = path.trim_left_matches('/');
        println!("[ramdisk] Opening {}", path);

        let file = if self.files.contains_key(path) {
            self.files[path].clone()
        } else {
            // Create a new file
            let new_file = Arc::new(RwLock::new(File::new()));
            self.files.insert(String::from(path), new_file.clone());
            new_file
        };

        // Make a new communication handle pair
        let (handle, client_handle) = syscalls::new_rendezvous()
            .map_err(|e| {println!("[tcp] Couldn't create Rendezvous {:?}", e);})?;

        // Start a thread
        thread::spawn(move || {
            handle_file(file, handle);
        });

        // Return the other handle to the client
        Ok(client_handle)
    }
}

/// Serve messages received from a communication channel
/// reading and writing data from a file
fn handle_file(file: Arc<RwLock<File>>,
               comm_handle: CommHandle) {
    println!("[ramdisk thread] count: {}", Arc::strong_count(&file));

    loop {
        match syscalls::receive(&comm_handle) {
            Ok(syscalls::Message::Long(
                message::WRITE,
                MessageData::Value(length),
                MessageData::MemoryHandle(handle))) => {

                let u8_slice = handle.as_slice::<u8>(length as usize);

                println!("[ramdisk] Writing {} bytes", length);

                // Append data to file
                file.write().data.extend_from_slice(u8_slice);

                // Return success
                syscalls::send(&comm_handle,
                               syscalls::Message::Short(
                                   message::OK, length, 0));
            }
            Ok(syscalls::Message::Short(
                message::READ, start, length)) => {

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
            Ok(syscalls::Message::Short(
                message::CLOSE, _, _)) => {
                // Close this file handler, dropping comm_handle
                return;
            }
            Ok(msg) => {
                println!("[ramdisk handle_file] -> {:?}", msg);
            }
            Err(syscalls::SYSCALL_ERROR_RECV_BLOCKING) => {
                // Waiting for a message
                // => Send an error message
                syscalls::send(&comm_handle,
                               syscalls::Message::Short(
                                   message::ERROR, 0, 0));
                // Wait and try again
                syscalls::thread_yield();
            },
            Err(syscalls::SYSCALL_ERROR_CLOSED) => {
                // Other Rendezvous handles have been dropped
                return;
            },
            Err(code) => {
                println!("[ramdisk handle_file] Receive error {}", code);
                // Wait and try again
                syscalls::thread_yield();
            }
        }
    }
}

fn handle_directory(directory: Arc<RwLock<Directory>>,
                    comm_handle: CommHandle) {
    loop {
        match syscalls::receive(&comm_handle) {
            Ok(Message::Long(
                message::OPEN,
                MessageData::Value(length),
                MessageData::MemoryHandle(handle))) => {
                // Get the path string and try to open it
                let u8_slice = handle.as_slice::<u8>(length as usize);
                if let Ok(path) = str::from_utf8(u8_slice) {
                    if let Ok(handle) = directory.write().open(path) {
                        // Success! Return handle
                        syscalls::send(&comm_handle,
                                       syscalls::Message::Long(
                                           message::COMM_HANDLE,
                                           handle.into(), 0.into()));
                    } else {
                        // Error opening path
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
            Ok(Message::Short(
                message::QUERY, _, _)) => {
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
\"short\": 'Ramdisk directory',
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
            Ok(message) => {
                println!("[ramdisk] Received unexpected message {:?}", message);
            },
            Err(syscalls::SYSCALL_ERROR_RECV_BLOCKING) => {
                // Waiting for a message
                // => Send an error message
                syscalls::send(&STDIN,
                               syscalls::Message::Short(
                                   message::ERROR, 0, 0));
                // Wait and try again
                syscalls::thread_yield();
            },
            Err(syscalls::SYSCALL_ERROR_CLOSED) => {
                // Other Rendezvous handles have been dropped
                return;
            },
            Err(code) => {
                println!("[tcp] Receive error {}", code);
                // Wait and try again
                syscalls::thread_yield();
            }
        }
    }
}

#[no_mangle]
fn main() {
    println!("[ramdisk] Starting ramdisk");

    let mut fs = Directory::new();

    handle_directory(Arc::new(RwLock::new(fs)), STDIN);
}
