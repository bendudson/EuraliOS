
use x86_64::{
    structures::paging::{
        mapper::MapToError, FrameAllocator, Mapper, PageTableFlags, Size4KiB,
    },
    VirtAddr,
};

// Fixed heap for the kernel
pub const HEAP_START: usize = 0x_4444_4444_0000;
pub const HEAP_SIZE: usize = 100 * 1024; // 100 KiB

use crate::memory;

pub fn init_heap(
    mapper: &mut impl Mapper<Size4KiB>,
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
) -> Result<(), MapToError<Size4KiB>> {

    memory::allocate_pages_mapper(
        mapper,
        frame_allocator,
        VirtAddr::new(HEAP_START as u64),
        HEAP_SIZE as u64,
        PageTableFlags::PRESENT | PageTableFlags::WRITABLE)?;

    unsafe {
        ALLOCATOR.lock().init(HEAP_START, HEAP_SIZE);
    }

    Ok(())
}

use linked_list_allocator::LockedHeap;

#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap::empty();
