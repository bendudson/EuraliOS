////////////////////////////
// Thread library
//
// Interface here:
//   https://doc.rust-lang.org/book/ch16-01-threads.html
//
// std implementation is here:
//  - spawn
//    https://doc.rust-lang.org/src/std/thread/mod.rs.html#646
//  - Thread::new
//    https://github.com/rust-lang/rust/blob/master/library/std/src/sys/unix/thread.rs
//

extern crate alloc;
use alloc::boxed::Box;

use crate::syscalls::{self, SyscallError};

/// Spawn a new thread with closure
///
/// The spawned thread may outlive the caller, so all
/// variables captured must be moved or have static lifetime.
///
/// thread::spawn(move || {
///   // Code which captures from environment
/// });
///
pub fn spawn<F>(f: F) -> Result<(), SyscallError>
where
    F: FnOnce() -> (),
    F: Send + 'static,
{
    launch(Box::new(f))
}

/// Launch a thread by calling the low-level syscalls
///
fn launch(p: Box<dyn FnOnce()>) -> Result<(), SyscallError>
{
    // Note: A Box<dyn FnOnce()> is a fat pointer,
    // containing a pointer to heap allocated memory
    // along with the function pointer. To convert to
    // a thin pointer (memory address) we first need
    // to move the fat pointer onto the heap by putting
    // into a Box, then get a pointer to that.
    let p = Box::into_raw(Box::new(p));

    // Get thin pointer as memory address
    if let Err(sys_err) = syscalls::thread_spawn(thread_start,
                                                 p as *mut () as usize) {
        // Could not launch thread. Reconstruct Box so that
        // the contents can be dropped
        let _ = unsafe {Box::from_raw(p)};
        return Err(sys_err);
    }

    // This function is called by syscalls::thread_spawn
    extern "C" fn thread_start(main: usize) {
        // Convert address back to Box containing the Box<dyn FnOnce()>
        // fat pointer, then call it.
        unsafe {Box::from_raw(main as *mut Box<dyn FnOnce()>)()};
    }
    Ok(())
}
