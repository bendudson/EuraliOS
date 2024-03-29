//! Kernel heap allocator
//!
//! Uses the `linked_list_allocator` crate to manage a fixed size heap
//! Used to store kernel data structures, including:
//! - Thread objects (in Box<Thread>)
//! - Stacks for kernel threads

use x86_64::{
    structures::paging::{
        mapper::MapToError, FrameAllocator, Mapper, PageTableFlags, Size4KiB,
    },
    VirtAddr,
};

// Fixed heap for the kernel
pub const HEAP_START: usize = 0x_4444_4444_0000;
pub const HEAP_SIZE: usize = 1024 * 1024; // 1 Mb

use crate::memory;

pub fn init_heap(
    mapper: &mut impl Mapper<Size4KiB>,
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
) -> Result<(), MapToError<Size4KiB>> {

    memory::allocate_pages_mapper(
        frame_allocator,
        mapper,
        VirtAddr::new(HEAP_START as u64),
        HEAP_SIZE as u64,
        PageTableFlags::PRESENT | PageTableFlags::WRITABLE)?;

    unsafe {
        ALLOCATOR.lock().init(HEAP_START as *mut u8, HEAP_SIZE);
    }

    Ok(())
}

use linked_list_allocator::LockedHeap;

#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap::empty();
