#![no_std]
#![no_main]

extern crate alloc;
use alloc::collections::btree_map::BTreeMap;
use alloc::{string::String, sync::Arc, vec::Vec};
use alloc::format;
use core::{str, cmp};

use spin::RwLock;

use euralios_std::{println,
                   server::{FileLike, DirLike, handle_directory},
                   message,
                   syscalls::{self, STDIN},
                   sys::path::MAIN_SEP_STR};

/// Represents a file as a bag of bytes
struct File {
    data: Vec<u8>
}

impl File {
    fn new() -> Self {
        File{data: Vec::new()}
    }
}

impl FileLike for File {
    fn len(&self) -> usize {
        self.data.len()
    }
    fn read(&self, start: usize, buffer: &mut [u8]) -> Result<usize, syscalls::SyscallError> {
        let end = cmp::min(start + buffer.len(), self.data.len());
        if start >= end {
            return Err(syscalls::SYSCALL_ERROR_NO_DATA);
        }
        let size = end - start;
        println!("[ramdisk] Reading {} bytes", size);
        buffer[..size].copy_from_slice(&self.data[start..end]);
        Ok(size)
    }
    fn write(&mut self, start: usize, buffer: &[u8]) -> Result<usize, syscalls::SyscallError> {
        println!("[ramdisk] Writing {} bytes", buffer.len());
        self.data.extend_from_slice(buffer);
        Ok(buffer.len())
    }
    fn clear(&mut self) -> Result<(), syscalls::SyscallError> {
        self.data.clear();
        Ok(())
    }
}

/// A tree structure of directories containing File objects
///
/// All subdirectories and files are wrapped in Arc<RwLock<>> because:
/// - Multiple processes may hold handles to the same directory or
///   file
/// - Hard links where multiple files point to the same data
pub struct Directory {
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
}

impl DirLike for Directory {
    /// Lookup and return shared reference to a directory
    fn get_dir(&self, name: &str) -> Result<Arc<RwLock<dyn DirLike + Send + Sync>>, syscalls::SyscallError> {
        if self.subdirs.contains_key(name) {
            Ok(self.subdirs[name].clone())
        } else {
            Err(syscalls::SYSCALL_ERROR_NOTFOUND)
        }
    }
    /// Lookup and return shared reference to a file
    fn get_file(&self, name: &str) -> Result<Arc<RwLock<dyn FileLike + Send + Sync>>, syscalls::SyscallError> {
        if self.files.contains_key(name) {
            Ok(self.files[name].clone())
        } else {
            Err(syscalls::SYSCALL_ERROR_NOTFOUND)
        }
    }

    fn query(&self) -> String {
        // Make a list of files separated with commas.
        // Each is a dictionary with a "name" key
        let file_list = {
            let mut s = String::new();
            let mut it = self.files.keys().peekable();
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
            let mut it = self.subdirs.keys().peekable();
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

        // Combine into a String and return
        format!("{{
\"short\": \"Ramdisk directory\",
\"messages\": [{{\"name\": \"open\",
                 \"tag\": {open_tag}}},
               {{\"name\": \"query\",
                 \"tag\": {query_tag}}}],
\"subdirs\": [{subdir_list}],
\"files\": [{file_list}]}}",
                open_tag = message::OPEN,
                query_tag = message::QUERY,
                file_list = file_list,
                subdir_list = subdir_list)
    }

    /// Make a sub-directory
    fn make_dir(&mut self, path: &str) -> Result<Arc<RwLock<dyn DirLike + Send + Sync>>, syscalls::SyscallError> {
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
        self.subdirs.insert(String::from(path), new_dir.clone());
        Ok(new_dir)
    }
    /// Create a new file, returning a shared reference
    fn make_file(&mut self, name: &str) -> Result<Arc<RwLock<dyn FileLike + Send + Sync>>, syscalls::SyscallError> {
        println!("[ramdisk] Making file {}", name);
        let new_file = Arc::new(RwLock::new(File::new()));
        self.files.insert(String::from(name), new_file.clone());
        Ok(new_file)
    }
    /// Delete a file
    fn remove_file(&mut self, path: &str) -> Result<Arc<RwLock<dyn FileLike + Send + Sync>>, syscalls::SyscallError> {
        let path = path.trim_start_matches('/');
        println!("[ramdisk] Removing file {}", path);

        if let Some(file) = self.files.remove(path) {
            Ok(file)
        } else {
            Err(syscalls::SYSCALL_ERROR_NOTFOUND)
        }
    }
}

#[no_mangle]
fn main() {
    println!("[ramdisk] Starting ramdisk");

    let fs = Directory::new();

    handle_directory(Arc::new(RwLock::new(fs)), STDIN.clone(), true);
}
