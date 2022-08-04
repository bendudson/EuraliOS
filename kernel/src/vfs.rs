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
    pub fn mount(&mut self,
                 path: &str,
                 rendezvous: Arc<RwLock<Rendezvous>>) {
        self.0.write().push((String::from(path), rendezvous));
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
}
