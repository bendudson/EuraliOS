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
                 handle: Arc<RwLock<Rendezvous>>) {
        self.0.write().push((String::from(path), handle));
    }

    /// Open a path, returning a handle to read/write
    pub fn open(&self,
                path: &str) -> Option<Arc<RwLock<Rendezvous>>> {
        if let Some((_mount, rv)) =
            self.0.read().iter().find(|&(mount, _rv)| mount == path) {
                Some(rv.clone())
            } else {
                None
            }
    }
}
