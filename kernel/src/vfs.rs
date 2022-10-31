//! Virtual File System

use spin::RwLock;
use alloc::{vec::Vec, sync::Arc};
use alloc::string::String;
use core::convert::From;

use crate::rendezvous::Rendezvous;

/// Virtual File System type
#[derive(Clone)]
pub struct VFS(Arc<RwLock<Vec<(String, Arc<RwLock<Rendezvous>>)>>>);

impl From<Vec<(String, Arc<RwLock<Rendezvous>>)>> for VFS {
    fn from(
        mounts: Vec<(String, Arc<RwLock<Rendezvous>>)>
    ) -> Self {
        VFS(Arc::new(RwLock::new(mounts)))
    }
}

impl VFS {
    /// Create an empty set of mount points
    pub fn new() -> Self {
        VFS(Arc::new(RwLock::new(Vec::new())))
    }

    /// Add a mount point to the VFS
    ///
    /// The path will have leading and trailing whitespace removed,
    /// and all trailing '/' characters removed.
    ///
    /// It is expected, though not technically required, for the
    /// path to start with '/'
    pub fn mount(&mut self,
                 path: &str,
                 rendezvous: Arc<RwLock<Rendezvous>>) {
        let path = path.trim().trim_end_matches('/');
        self.0.write().push((String::from(path), rendezvous));
    }

    /// Remove a mount point from the VFS
    pub fn umount(&mut self,
                  path: &str) -> Result<(),()> {
        let mut mounts = self.0.write();
        if let Some(index) = mounts.iter().position(
            |mount_path| mount_path.0 == path) {
            // Found an index
            _ = mounts.swap_remove(index);
            return Ok(());
        }
        Err(())
    }

    /// Open a path, returning a handle to read/write and the
    /// length of the string matched.
    pub fn open(&self,
                path: &str) -> Option<(Arc<RwLock<Rendezvous>>, usize)> {
        let mounts = self.0.read();
        let mut found: Option<(usize, usize)> = None;
        for (i, mount_path) in mounts.iter().enumerate() {
            if path.starts_with(&mount_path.0) {
                let len = mount_path.0.len();
                if path.len() > len {
                    // The path should be a subdirectory
                    // - the next character in path should be "/"
                    // Note: str.len() is bytes, not characters
                    if path.as_bytes()[len] != b'/' {
                        // Not this path
                        continue;
                    }
                }
                // Choose the longest match
                if let Some((_, maxlen)) = found {
                    if len > maxlen {
                        found = Some((i, len));
                    }
                } else {
                    found = Some((i, len));
                }
            }
        }
        if let Some((ind, match_len)) = found {
            return Some((mounts[ind].1.clone(), match_len));
        }
        None
    }

    /// Return a list of mount points as a JSON string
    pub fn to_json(&self) -> String {
        let mounts = self.0.read();

        let mut s = String::new();
        s.push('[');
        for mount_path in mounts.iter() {
            s.push('"');
            s.push_str(&mount_path.0);
            s.push('"');
            s.push(',');
        }
        s.push(']');
        s
    }

    /// Make a copy of the internal state
    pub fn copy(&self) -> Self {
        VFS(Arc::new(RwLock::new(self.0.read().clone())))
    }
}
