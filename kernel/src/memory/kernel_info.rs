//! A page which is mapped read-only into every user program's address
//! space. It can be used to provide time-sensitive information.
//!
use x86_64::{
    structures::paging::{
        page::Page, frame::PhysFrame,
        mapper::MapToError, FrameAllocator, Mapper, PageTableFlags, Size4KiB,
    },
    VirtAddr, PhysAddr
};

use core::sync::atomic::{AtomicU64, Ordering};

static FRAME_PHYSADDR: AtomicU64 = AtomicU64::new(0);

/// KernelInfo virtual address in kernel address space
static FRAME_VIRTADDR: AtomicU64 = AtomicU64::new(0);

/// KernelInfo virtual address in user address space
const KERNELINFO_VIRTADDR: u64 = 0x4fff000;

pub struct KernelInfo {
    // These are set in time::pit_interrupt_notify()
    pub pit_ticks: u64, // Number of PIT ticks since restart
    pub last_tsc: u64, // TSC value at last pit_ticks update
    pub tsc_per_pit: u64, // Change in TSC ticks per PIT tick
}

/// Initialise a frame to hold the KernelInfo struct
pub fn init(
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

pub fn add_to_user_table(
    mapper: &mut impl Mapper<Size4KiB>,
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
) -> Result<(), MapToError<Size4KiB>> {
    let page = Page::containing_address(
        VirtAddr::new(KERNELINFO_VIRTADDR));
    let frame = PhysFrame::containing_address(
        PhysAddr::new(FRAME_PHYSADDR.load(Ordering::Relaxed)));

    unsafe {
        mapper.map_to(page,
                      frame,
                      // Page not writable
                      PageTableFlags::PRESENT |
                      PageTableFlags::USER_ACCESSIBLE,
                      frame_allocator)?.flush();
    }
    Ok(())
}
