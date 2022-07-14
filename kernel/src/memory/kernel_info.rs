//! A page which is mapped read-only into every user program's address
//! space. It can be used to provide time-sensitive information.
//!
use x86_64::{
    structures::paging::{
        mapper::MapToError, FrameAllocator, Mapper, PageTableFlags, Size4KiB,
    },
    VirtAddr, PhysAddr
};

use core::sync::atomic::{AtomicU64, Ordering};

static FRAME_PHYSADDR: AtomicU64 = AtomicU64::new(0);
static FRAME_VIRTADDR: AtomicU64 = AtomicU64::new(0);

pub struct KernelInfo {
    pit_ticks: u64, // Number of PIT ticks since restart
    last_tsc: u64, // TSC value at last pit_ticks update
    tsc_per_pit: u64, // Change in TSC ticks per PIT tick
}

/// Initialise a frame to hold the KernelInfo struct
pub fn init(
    mapper: &mut impl Mapper<Size4KiB>,
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
    physical_memory_offset: VirtAddr
) -> Result<(), MapToError<Size4KiB>> {

    // Get one frame
    let frame = frame_allocator
        .allocate_frame()
        .ok_or(MapToError::FrameAllocationFailed)?;

    // This frame is already mapped. Save its physical and virtual addresses
    FRAME_PHYSADDR.store(frame.start_address().as_u64(), Ordering::Relaxed);
    FRAME_VIRTADDR.store(physical_memory_offset.as_u64() + frame.start_address().as_u64(),
                         Ordering::Relaxed);
    Ok(())
}

pub fn get_ref() -> &'static KernelInfo {
    let ptr = FRAME_VIRTADDR.load(Ordering::Relaxed) as *const KernelInfo;
    unsafe{&(*ptr)}
}

pub fn get_mut() -> &'static mut KernelInfo {
    let ptr = FRAME_VIRTADDR.load(Ordering::Relaxed) as *mut KernelInfo;
    unsafe{&mut (*ptr)}
}

