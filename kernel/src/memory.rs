
use x86_64::{
    structures::paging::{Page, PageTable, PhysFrame,
                         Size4KiB, FrameAllocator, OffsetPageTable,
                         mapper::MapToError, PageTableFlags, Mapper
    },
    PhysAddr, VirtAddr
};

/// The level 4, 3 and 2 page table index
/// to access the level 1 page where stacks are stored
const THREAD_STACK_PAGE_INDEX: [u8; 3] = [5, 0, 0];

use crate::println;
use crate::allocator;
use crate::syscalls;
use bootloader::BootInfo;

use core::arch::asm;

struct MemoryInfo {
    boot_info: &'static BootInfo,

    physical_memory_offset: VirtAddr,

    /// Allocate empty frames
    frame_allocator: MultilevelBitmapFrameAllocator,

    /// Kernel page table physical address
    kernel_l4_table: &'static mut PageTable
}

/// Store BootInfo struct and other useful things for later use
/// This is set in the init() function and should not be
/// modified after that.
static mut MEMORY_INFO: Option<MemoryInfo> = None;

/// Initialize a new OffsetPageTable.
///
/// This function must be only called once to avoid aliasing `&mut`
/// references (which is undefined behavior).
pub fn init(boot_info: &'static BootInfo) {
    use x86_64::instructions::interrupts;

    interrupts::without_interrupts(|| {
        let mut memory_size = 0;
        for region in boot_info.memory_map.iter() {
            let start_addr = region.range.start_addr();
            let end_addr = region.range.end_addr();
            memory_size += end_addr - start_addr;
            println!("MEM [{:#016X}-{:#016X}] {:?}", start_addr, end_addr, region.region_type);
        }
        println!("Memory size: {} KB\n", memory_size >> 10);

        let physical_memory_offset = VirtAddr::new(boot_info.physical_memory_offset);

        println!("Physical memory offset: {:#016X}", physical_memory_offset.as_u64());

        let level_4_table = unsafe {active_level_4_table(physical_memory_offset)};

        // Initialise the memory mapper
        let mut mapper = unsafe {OffsetPageTable::new(level_4_table, physical_memory_offset)};
        let mut frame_allocator = unsafe {
            MultilevelBitmapFrameAllocator::init(&boot_info.memory_map,
                                                 physical_memory_offset)
        };

        allocator::init_heap(&mut mapper, &mut frame_allocator)
            .expect("heap initialization failed");

        // Store boot_info for later calls
        unsafe { MEMORY_INFO = Some(MemoryInfo {
            boot_info,
            physical_memory_offset,
            frame_allocator,
            kernel_l4_table: level_4_table
        }) };
    });
}

/// This should only be called from the init function
/// because each call will result in a mutable reference
unsafe fn active_level_4_table(physical_memory_offset: VirtAddr)
                               -> &'static mut PageTable {
    use x86_64::registers::control::Cr3;

    let (level_4_table_frame, _) = Cr3::read();

    let phys = level_4_table_frame.start_address();
    let virt = physical_memory_offset + phys.as_u64();
    let page_table_ptr: *mut PageTable = virt.as_mut_ptr();

    &mut *page_table_ptr // unsafe
}

/// Create a new page table
///
/// Returns
/// -------
///
/// - A pointer to the PageTable (virtual address in kernel mapped pages)
/// - The physical address which can be written to cr3
///
fn create_empty_pagetable() -> (*mut PageTable, u64) {
    // Need to borrow as mutable so that we can allocate new frames
    // and so modify the frame allocator
    let memory_info = unsafe {MEMORY_INFO.as_mut().unwrap()};

    // Get a frame to store the level 4 table
    let level_4_table_frame = memory_info.frame_allocator.allocate_frame().unwrap();
    let phys = level_4_table_frame.start_address(); // Physical address
    let virt = memory_info.physical_memory_offset + phys.as_u64(); // Kernel virtual address
    let page_table_ptr: *mut PageTable = virt.as_mut_ptr();

    // Clear all entries in the page table
    unsafe {
        (*page_table_ptr).zero();
    }

    (page_table_ptr, phys.as_u64())
}

/// Copy a set of pagetables
fn copy_pagetables(level_4_table: &PageTable) -> (*mut PageTable, u64) {
    // Create a new level 4 pagetable
    let (table_ptr, table_physaddr) = create_empty_pagetable();
    let table = unsafe {&mut *table_ptr};

    fn copy_pages_rec(physical_memory_offset: VirtAddr,
                      from_table: &PageTable, to_table: &mut PageTable,
                      level: u16) {
        for (i, entry) in from_table.iter().enumerate() {
            if !entry.is_unused() {
                if (level == 1) || entry.flags().contains(PageTableFlags::HUGE_PAGE) {
                    // Maps a frame, not a page table
                    to_table[i].set_addr(entry.addr(), entry.flags());
                } else {
                    // Create a new table at level - 1
                    let (new_table_ptr, new_table_physaddr) = create_empty_pagetable();
                    let to_table_m1 = unsafe {&mut *new_table_ptr};

                    // Point the entry to the new table
                    to_table[i].set_addr(PhysAddr::new(new_table_physaddr),
                                         entry.flags());

                    // Get reference to the input level-1 table
                    let from_table_m1 = {
                        let virt = physical_memory_offset + entry.addr().as_u64();
                        unsafe {& *virt.as_ptr()}
                    };

                    // Copy level-1 entries
                    copy_pages_rec(physical_memory_offset, from_table_m1, to_table_m1, level - 1);
                }
            }
        }
    }

    let memory_info = unsafe {MEMORY_INFO.as_mut().unwrap()};
    copy_pages_rec(memory_info.physical_memory_offset, level_4_table, table, 4);

    return (table_ptr, table_physaddr)
}

/// Creates a PageTable containing only kernel pages
///
/// Copies the kernel pagetables into a new set of tables
///
/// Returns
/// -------
///
/// - A pointer to the PageTable (virtual address in kernel mapped pages)
/// - The physical address which can be written to cr3
///
pub fn create_kernel_only_pagetable() -> (*mut PageTable, u64) {
    let memory_info = unsafe {MEMORY_INFO.as_mut().unwrap()};

    copy_pagetables(memory_info.kernel_l4_table)
}

/// Switch to the specified page table
///
/// # Input
///
/// physaddr   Physical address of the L4 page table
pub fn switch_to_pagetable(physaddr: u64) {
    unsafe {
        asm!("mov cr3, {addr}",
             addr = in(reg) physaddr);
    }
}

pub fn switch_to_kernel_pagetable() {
    let memory_info = unsafe {MEMORY_INFO.as_mut().unwrap()};
    let phys_addr = (memory_info.kernel_l4_table as *mut PageTable as u64)
        - memory_info.physical_memory_offset.as_u64();
    switch_to_pagetable(phys_addr);
}

pub fn active_pagetable_physaddr() -> u64 {
    let mut physaddr: u64;
    unsafe {
        asm!("mov {addr}, cr3",
             addr = out(reg) physaddr);
    }
    physaddr
}

pub fn active_pagetable_ptr() -> *mut PageTable {
    let memory_info = unsafe {MEMORY_INFO.as_mut().unwrap()};
    let virt = memory_info.physical_memory_offset + active_pagetable_physaddr();
    virt.as_mut_ptr()
}

///////////////////////////////////////////////////////////////////////
// Routines to allocate memory in a single page table

/// Allocate pages in the specified page table
/// starting at the page containing virtual address \p start_addr
/// and large enough to contain \p size bytes.
///
/// \p flags  PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
pub fn allocate_pages_mapper(
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
    mapper: &mut impl Mapper<Size4KiB>,
    start_addr: VirtAddr,
    size: u64,
    flags: PageTableFlags)
    -> Result<(), MapToError<Size4KiB>> {

    let page_range = {
        let end_addr = start_addr + size - 1u64;
        let start_page = Page::containing_address(start_addr);
        let end_page = Page::containing_address(end_addr);
        Page::range_inclusive(start_page, end_page)
    };

    for page in page_range {
        let frame = frame_allocator
            .allocate_frame()
            .ok_or(MapToError::FrameAllocationFailed)?;
        unsafe {
            mapper.map_to(page,
                          frame,
                          flags,
                          frame_allocator)?.flush()
        };
    }

    Ok(())
}

pub fn allocate_pages(level_4_table: *mut PageTable,
                      start_addr: VirtAddr,
                      size: u64,
                      flags: PageTableFlags)
                      -> Result<(), MapToError<Size4KiB>> {

    let memory_info = unsafe {MEMORY_INFO.as_mut().unwrap()};

    let mut mapper = unsafe {
        OffsetPageTable::new(&mut *level_4_table,
                             memory_info.physical_memory_offset)};

    allocate_pages_mapper(
        &mut memory_info.frame_allocator,
        &mut mapper,
        start_addr, size, flags)
}

/// Allocate pages in the active page table
///
/// Inputs
/// ------
///
/// start_addr  Virtual address in the first page
/// size        Size of the region in bytes.
/// flags       Set permissions / properties
///
pub fn allocate_active_pages(
    start_addr: VirtAddr,
    size: u64,
    flags: PageTableFlags)
    -> Result<(), MapToError<Size4KiB>> {

    let memory_info = unsafe {MEMORY_INFO.as_mut().unwrap()};
    let level_4_table = unsafe {active_level_4_table(memory_info.physical_memory_offset)};

    allocate_pages(&mut *level_4_table, start_addr, size, flags)
}

/// Create user-accessible pages, which are allocated on demand
/// ie when written to.
///
/// One frame is allocated, and made writable through the first page in the range.
/// The other pages point to the same frame but are read-only. Writes to those
/// frames trigger a page fault, and the handler allocates a frame.
///
/// This allows large user heaps to be created without using a lot of memory.
pub fn create_user_ondemand_pages(
    level_4_physaddr: u64,
    start_addr: VirtAddr,
    size: u64)
    -> Result<(), MapToError<Size4KiB>> {

    let memory_info = unsafe {MEMORY_INFO.as_mut().unwrap()};
    let frame_allocator = &mut memory_info.frame_allocator;

    let l4_table: &mut PageTable = unsafe {
        &mut *(memory_info.physical_memory_offset
               + level_4_physaddr).as_mut_ptr()};

    let mut mapper = unsafe {
        OffsetPageTable::new(l4_table,
                             memory_info.physical_memory_offset)};

    let page_range = {
        let end_addr = start_addr + size - 1u64;
        let start_page = Page::containing_address(start_addr);
        let end_page = Page::containing_address(end_addr);
        Page::range_inclusive(start_page, end_page)
    };

    // Only allocating one frame
    let frame = frame_allocator
        .allocate_frame()
        .ok_or(MapToError::FrameAllocationFailed)?;

    for page in page_range {
        unsafe {
            mapper.map_to_with_table_flags(page,
                                           frame,
                                           // Page not writable
                                           PageTableFlags::PRESENT |
                                           PageTableFlags::USER_ACCESSIBLE,
                                           // Parent table flags include writable
                                           PageTableFlags::PRESENT |
                                           PageTableFlags::WRITABLE |
                                           PageTableFlags::USER_ACCESSIBLE,
                                           frame_allocator)?.flush()
        };
    }

    // Make one page writable, so this 'owns' the frame
    unsafe {
        mapper.update_flags(page_range.start,
                            PageTableFlags::PRESENT |
                            PageTableFlags::WRITABLE |
                            PageTableFlags::USER_ACCESSIBLE);
    }

    Ok(())
}

/// Allocates a consecutive set of frames
///
/// start_addr      Starting virtual address in page table
/// num_frames      Number of consecutive frames
/// max_physaddr    Maximum physical address
///                 e.g 32-bit addressable 0xFFFF_FFFF
pub fn create_consecutive_pages(
    level_4_physaddr: u64,
    start_addr: VirtAddr,
    num_frames: u64,
    max_physaddr: u64)
    -> Result<PhysAddr, MapToError<Size4KiB>> {

    let memory_info = unsafe {MEMORY_INFO.as_mut().unwrap()};
    let frame_allocator = &mut memory_info.frame_allocator;

    // Try to allocate a consecutive set of frames
    let start_frame = frame_allocator
        .allocate_consecutive_frames(num_frames, max_physaddr)
        .ok_or(MapToError::FrameAllocationFailed)?;

    let frame_range = PhysFrame::range(start_frame, start_frame + num_frames);

    let page_range = {
        let start_page = Page::containing_address(start_addr);
        Page::range(start_page, start_page + num_frames)
    };

    let l4_table: &mut PageTable = unsafe {
        &mut *(memory_info.physical_memory_offset
               + level_4_physaddr).as_mut_ptr()};

    let mut mapper = unsafe {
        OffsetPageTable::new(l4_table,
                             memory_info.physical_memory_offset)};

    for (page, frame) in page_range.zip(frame_range) {
        println!("Page: {:?} -> Frame: {:?}", page, frame);

        unsafe {
            mapper.map_to_with_table_flags(page,
                                           frame,
                                           // Writeable by user
                                           PageTableFlags::PRESENT |
                                           PageTableFlags::WRITABLE |
                                           PageTableFlags::USER_ACCESSIBLE,
                                           // Parent table flags include writable
                                           PageTableFlags::PRESENT |
                                           PageTableFlags::WRITABLE |
                                           PageTableFlags::USER_ACCESSIBLE,
                                           frame_allocator)?.flush()
        };
    }
    Ok(start_frame.start_address())
}

///////////////////////////////////////////////////////////////////////

const MEMORY_CHUNK_L4_ENTRY: usize = 5;
const MEMORY_CHUNK_L3_FIRST: usize = 1;
const MEMORY_CHUNK_L3_LAST: usize = 511;

/// Find the starting address of an available chunk of pages
///
/// Returns the index and virtual address of the start of the chunk
/// or None if no chunks available
pub fn find_available_page_chunk(
    level_4_physaddr: u64
) -> Option<VirtAddr> {

    let memory_info = unsafe {MEMORY_INFO.as_mut().unwrap()};

    let l4_table: &mut PageTable = unsafe {
        &mut *(memory_info.physical_memory_offset
               + level_4_physaddr).as_mut_ptr()};
    let l4_entry = &mut l4_table[MEMORY_CHUNK_L4_ENTRY];

    if l4_entry.is_unused() {
        // L3 table not allocated -> Create
        let (_new_table_ptr, new_table_physaddr) = create_empty_pagetable();
        l4_entry.set_addr(PhysAddr::new(new_table_physaddr),
                          PageTableFlags::PRESENT |
                          PageTableFlags::WRITABLE |
                          PageTableFlags::USER_ACCESSIBLE);
    }
    let l3_table: &PageTable = unsafe {
        & *(memory_info.physical_memory_offset
            + l4_entry.addr().as_u64()).as_ptr()};

    // Each entry in l3_table from FIRST to LAST inclusive
    // is a separate chunk
    for ind in MEMORY_CHUNK_L3_FIRST..=MEMORY_CHUNK_L3_LAST {
        let entry = &l3_table[ind];
        if entry.is_unused() {
            // Found an empty chunk
            // Convert L4 and L3 index into virtual address
            return Some(VirtAddr::new(((MEMORY_CHUNK_L4_ENTRY as u64) << 39) |
                                      (ind << 30) as u64));
        }
    }
    None
}

/// Free a memory chunk, releasing the pages back to the frame allocator
pub fn free_page_chunk(
    level_4_physaddr: u64,
    address: VirtAddr
) -> Result<(), usize> {

    let memory_info = unsafe {MEMORY_INFO.as_mut().unwrap()};

    // Check that the p4 and p3 index is in range
    if usize::from(address.p4_index()) != MEMORY_CHUNK_L4_ENTRY {
        // Incorrect P4 entry
        return Err(syscalls::SYSCALL_ERROR_PARAM);
    }
    if (usize::from(address.p3_index()) < MEMORY_CHUNK_L3_FIRST) ||
        (usize::from(address.p3_index()) > MEMORY_CHUNK_L3_LAST) {
            // P3 out of range
            return Err(syscalls::SYSCALL_ERROR_PARAM);
        }

    // Follow page table addresses
    let l4_table: &PageTable = unsafe {
        & *(memory_info.physical_memory_offset
            + level_4_physaddr).as_mut_ptr()};
    let l4_entry = &l4_table[MEMORY_CHUNK_L4_ENTRY];

    if l4_entry.is_unused() {
        // No chunks allocated
        return Err(syscalls::SYSCALL_ERROR_MEMORY);
    }

    let l3_table: &mut PageTable = unsafe {
        &mut *(memory_info.physical_memory_offset
               + l4_entry.addr().as_u64()).as_mut_ptr()};
    let l3_entry = &mut l3_table[address.p3_index()];

    if l3_entry.is_unused() {
        // Not allocated => Double free?
        return Err(syscalls::SYSCALL_ERROR_DOUBLEFREE);
    }

    // Free page tables and pages recursively
    free_pages_rec(memory_info.physical_memory_offset,
                   &mut memory_info.frame_allocator,
                   l3_entry.addr(),
                   2); // Level 2

    // Mark entry as empty
    l3_entry.set_unused();

    Ok(())
}

///////////////////////////////////////////////////////////////////////

/// Recursively free all pages and page tables, including the page
/// table at the given table_physaddr.
fn free_pages_rec(physical_memory_offset: VirtAddr,
                  frame_allocator: &mut MultilevelBitmapFrameAllocator,
                  table_physaddr: PhysAddr,
                  level: u16) {
    let table = unsafe{&mut *(physical_memory_offset
                              + table_physaddr.as_u64())
                       .as_mut_ptr() as &mut PageTable};
    for entry in table.iter() {
        if !entry.is_unused() {
            if level == 1 || entry.flags().contains(PageTableFlags::HUGE_PAGE) {
                // Maps a frame, not a page table
                if entry.flags().contains(PageTableFlags::PRESENT |
                                          PageTableFlags::WRITABLE |
                                          PageTableFlags::USER_ACCESSIBLE)  {
                    // A user frame => deallocate
                    frame_allocator.deallocate_frame(
                        entry.frame().unwrap());
                }
            } else {
                // A page table
                free_pages_rec(physical_memory_offset,
                               frame_allocator,
                               entry.addr(),
                               level - 1);
            }
        }
    }
    // Free page table
    frame_allocator.deallocate_frame(
        PhysFrame::from_start_address(table_physaddr).unwrap());
}

/// Free all user-accessible pages and the page table frames
///
/// Note: Must not be called to free the current page tables
///       Switch to kernel pagetable before calling
pub fn free_user_pagetables(level_4_physaddr: u64) {
    let memory_info = unsafe {MEMORY_INFO.as_mut().unwrap()};

    free_pages_rec(memory_info.physical_memory_offset,
                   &mut memory_info.frame_allocator,
                   PhysAddr::new(level_4_physaddr),
                   4);
}

///////////////////////////////////////////////////////////////////////

/// Allocate memory for a thread's user stack
///
/// Uses 8 pages per thread: 7 for user stack, one guard page
///
/// # Returns
///
/// (user_stack_start, user_stack_end)
///
pub fn allocate_user_stack(
    level_4_table: *mut PageTable
) -> Result<(u64, u64), &'static str> {

    let memory_info = unsafe {MEMORY_INFO.as_mut().unwrap()};

    let mut table = unsafe {&mut *level_4_table};
    for index in THREAD_STACK_PAGE_INDEX {
        let entry = &mut table[index as usize];
        if entry.is_unused() {
            // Page not allocated -> Create page table
            let (_new_table_ptr, new_table_physaddr) = create_empty_pagetable();
            entry.set_addr(PhysAddr::new(new_table_physaddr),
                           PageTableFlags::PRESENT |
                           PageTableFlags::WRITABLE |
                           PageTableFlags::USER_ACCESSIBLE);
        }
        table = unsafe {&mut *(memory_info.physical_memory_offset
                               + entry.addr().as_u64()).as_mut_ptr()};
    }

    // Table should now be the level 1 page table
    //
    // Find an unused set of 8 pages. The lowest page is always unused
    // (guard), but the first should be used so look in pages
    // (1 + 8*n) where n=0..64
    //
    // Choose a random n to start looking, and check entries
    // sequentially from there. For now just use process::unique_id
    use crate::process;
    let n_start = process::unique_id(); // Modulo 64 soon
    for i in 0..64 {
        let n = ((n_start + i) % 64) as usize;

        if table[n * 8 + 1].is_unused() {
            // Found an empty slot:
            //  [n * 8] -> Empty (guard)
            //  [n * 8 + 1] -> User stack (read-only)
            //      ...
            //  [n * 8 + 7] -> User stack (writable)

            // Note: Only one frame is going to be allocated, and the rest
            //       are going to be read-only references to the same frame.
            //       When a thread tries to write to them a page fault will
            //       be triggered and the frame allocated.
            let frame = memory_info.frame_allocator.allocate_frame()
                    .ok_or("Failed to allocate frame")?;

            for j in 1..7 {
                // These pages are read-only
                let entry = &mut table[n * 8 + j];
                entry.set_addr(frame.start_address(),
                               PageTableFlags::PRESENT |
                               PageTableFlags::USER_ACCESSIBLE);
            }
            let entry = &mut table[n * 8 + 7];
            entry.set_addr(frame.start_address(),
                           PageTableFlags::PRESENT |
                           PageTableFlags::WRITABLE | // Note!
                           PageTableFlags::USER_ACCESSIBLE);

            // Return the virtual addresses of the top of the kernel and user stacks
            let slot_address: u64 =
                ((THREAD_STACK_PAGE_INDEX[0] as u64) << 39) +
                ((THREAD_STACK_PAGE_INDEX[1] as u64) << 30) +
                ((THREAD_STACK_PAGE_INDEX[2] as u64) << 21) +
                (((n * 8) as u64) << 12);

            return Ok((slot_address + 4096,
                       slot_address + 8 * 4096)); // User stack
        }
    }

    Err("All thread stack slots full")
}

fn active_level_1_table_containing(
    addr: VirtAddr
) -> &'static mut PageTable {
    let memory_info = unsafe {MEMORY_INFO.as_mut().unwrap()};
    let mut table = unsafe{&mut (*active_pagetable_ptr())};

    for index in [addr.p4_index(),
                  addr.p3_index(),
                  addr.p2_index()] {

        let entry = &mut table[index];
        table = unsafe {&mut *(memory_info.physical_memory_offset
                               + entry.addr().as_u64()).as_mut_ptr()};
    }
    table
}

/// Allocate a read-only page which user code
/// has attempted to write to.
/// This is called by the page fault handler
pub fn allocate_missing_ondemand_frame(
    addr: VirtAddr
) -> Result<(), &'static str> {

    let table = active_level_1_table_containing(addr);
    let entry = &mut table[addr.p1_index()];

    if entry.flags() != (PageTableFlags::PRESENT |
                         PageTableFlags::USER_ACCESSIBLE) {
        return Err("Error: Unexpected table flags");
    }

    // Get a new frame and update page table
    let memory_info = unsafe {MEMORY_INFO.as_mut().unwrap()};
    let frame = memory_info.frame_allocator.allocate_frame()
        .ok_or("Could not allocate frame")?;

    entry.set_addr(frame.start_address(),
                   PageTableFlags::PRESENT |
                   PageTableFlags::WRITABLE |
                   PageTableFlags::USER_ACCESSIBLE);
    Ok(())
}

/// Free frames used for a thread stack
/// given virtual address
pub fn free_user_stack(
    stack_end: VirtAddr
) -> Result<(), &'static str> {
    let addr = stack_end - 1u64; // Address in last page
    let table = active_level_1_table_containing(addr);

    let memory_info = unsafe {MEMORY_INFO.as_mut().unwrap()};

    let iend = usize::from(addr.p1_index());
    for index in ((iend - 6)..=iend).rev() {
        let entry = &mut table[index];
        if entry.flags().contains(PageTableFlags::WRITABLE) {
            // Free this frame
            memory_info.frame_allocator.deallocate_frame(
                entry.frame().unwrap());
        }
        entry.set_flags(PageTableFlags::empty());
    }

    Ok(())
}

///////////////////////////////////////////////////////////////////////


/// Read the processor's Time Stamp Counter
/// uses RDTSC
/// https://www.felixcloutier.com/x86/rdtsc
fn time_stamp_counter() -> u64 {
    let counter: u64;
    unsafe{
        asm!("rdtsc",
             "shl rdx, 32", // High bits in EDX
             "mov edx, eax", // Low bits in EAX
             out("rdx") counter,
             out("rax") _, // Clobbers RAX
             options(pure, nomem, nostack)
        );
    }
    counter
}

///////////////////////////////////////////////////////////////////////

use bootloader::bootinfo::MemoryMap;
use bootloader::bootinfo::MemoryRegionType;

/// Return the index of a non-zero bit
///
/// Uses the BSF instruction: https://www.felixcloutier.com/x86/bsf
///
/// Assumes that at least one bit is not zero
fn nonzero_bit_index(bitmap: u32) -> u32 {
    let index: u32;
    unsafe {
        asm!("bsf eax, ecx",
             in("ecx") bitmap,
             lateout("eax") index,
             options(pure, nomem, nostack));
    }
    index
}

#[test_case]
fn test_nonzero_bit_index() {
    assert_eq!(nonzero_bit_index(1), 0);
    assert_eq!(nonzero_bit_index(32), 5);
}

/// Calculate the number of bitmap levels needed
///
/// Bitmaps are in chunks of 32, so each level multiplies the maximum
/// number of frames by 32.
fn num_levels_needed(num_frames: u64) -> usize {
    let mut max_frames = 32;
    let mut levels = 1;

    while num_frames > max_frames {
        levels += 1;
        max_frames *= 32;
    }
    levels
}

#[test_case]
fn test_num_levels_needed() {
    assert_eq!(num_levels_needed(1), 1);
    assert_eq!(num_levels_needed(32), 1);
    assert_eq!(num_levels_needed(33), 2);
    assert_eq!(num_levels_needed(1024), 2);
    assert_eq!(num_levels_needed(1025), 3);
    assert_eq!(num_levels_needed(33554432), 5);
}

/// Maximum number of levels supported. The maximum number of frames
/// is 32^levels, so 6 levels can keep track of 4Tb of 4k frames.
const FRAME_ALLOCATOR_MAX_LEVELS: usize = 6;

/// Size of the stack of available frames
/// Note: Must be >= bitmap chunk size (32)
const FRAME_ALLOCATOR_STACK_SIZE: usize = 32;

/// An allocator which uses bitmaps to keep track of available frames
///
/// At the lowest level one bit represents one frame (1 = available)
/// Higher levels indicate whether chunks of 32 bits at level-1 have ANY
/// non-zero bits. Multiple levels are used, until the top level has
/// only a single chunk of up to 32 bits.
///
pub struct MultilevelBitmapFrameAllocator {
    /// Virtual address of the first level 2 entry
    /// Each entry is 32 bits long, one bit per level-1 entry
    bitmap_virt_addr: [VirtAddr; FRAME_ALLOCATOR_MAX_LEVELS],

    /// Number of frames
    nframes: u64,

    /// Number of levels
    nlevels: usize,

    /// Physical start address of the frames
    frame_phys_addr: PhysAddr,

    /// Stack of up to FRAME_ALLOCATOR_STACK_SIZE frames
    frame_stack: [u64; FRAME_ALLOCATOR_STACK_SIZE],
    frame_stack_number: usize,
}

impl MultilevelBitmapFrameAllocator {

    /// Initialise a bitmap allocator
    ///
    /// This function is unsafe because the caller must guarantee
    /// that the memory map and physical memory offset is correct.
    pub unsafe fn init(memory_map: &'static MemoryMap,
                       physical_memory_offset: VirtAddr) -> Self {
        // get usable regions from memory map
        let mut usable_regions = memory_map
            .iter()
            .filter(|r| r.region_type == MemoryRegionType::Usable);

        _ = usable_regions.next(); // Discard the first region
        let region = usable_regions.next().unwrap();

        let start_addr = region.range.start_addr();
        let end_addr = region.range.end_addr();
        let nframes = region.range.end_frame_number - region.range.start_frame_number;
        let nlevels = num_levels_needed(nframes);

        let mut bitmap_virt_addr = [VirtAddr::new(0); FRAME_ALLOCATOR_MAX_LEVELS];
        let mut level_start_addr = start_addr;
        let mut nbits = nframes; // Number of bits needed at each level
        for level in 0..nlevels {
            bitmap_virt_addr[level] = physical_memory_offset + level_start_addr;
            let level_ptr = bitmap_virt_addr[level].as_mut_ptr() as *mut u32;

            let num_full_chunks = nbits >> 5;
            for i in 0..num_full_chunks {
                *(level_ptr.offset(i as isize)) = 0xFFFF_FFFF;
            }

            // May need final part-filled chunk
            let num_extra_bits = nbits & 31;
            if num_extra_bits > 0 {
                // Fill with ones, then shift to zero missing frames
                // note: Missing frames correspond to high bits so shift right
                *(level_ptr.offset(num_full_chunks as isize)) =
                    0xFFFF_FFFF >> (32 - num_extra_bits);
            }

            // Total number of chunks i.e. bits at next level
            nbits = num_full_chunks + if num_extra_bits > 0 {1} else {0};

            // Start address of the next level
            level_start_addr += nbits * 4u64;
        }
        // Number of bytes needed to store all bitmaps
        let bitmap_size_bytes = level_start_addr - start_addr;
        // Round up number of frames needed by adding 4095 and dividing by 4096
        let bitmap_size_frames = (bitmap_size_bytes + 4095) >> 12;

        println!("Region: {:#016X} - {:#016X}", start_addr, end_addr);
        println!("Frames: {} Levels: {} Reserved frames: {}",
                 nframes, nlevels, bitmap_size_frames);

        // Mark frames where bitmaps are stored as used
        // - Clear low bits in bitmaps corresponding to the used frames
        // - May need to clear multiple chunks and levels if the
        //   bitmap fills more than one chunk (32 frames).
        let mut nbits = bitmap_size_frames; // Number of bits to clear
        for level in 0..nlevels {
            let ptr = bitmap_virt_addr[level].as_mut_ptr() as *mut u32;

            let num_full_chunks = nbits >> 5;
            for i in 0..num_full_chunks {
                *(ptr.offset(i as isize)) = 0; // Clear
            }

            // May need to clear part of a chunk
            // Note: Clearing low bits so shift left
            let num_extra_bits = nbits & 31;
            if num_extra_bits > 0 {
                *(ptr.offset(num_full_chunks as isize)) =
                    (0xFFFF_FFFF << num_extra_bits) & 0xFFFF_FFFF;
            }

            if num_full_chunks == 0 {
                break; // Don't need to clear higher bitmaps
            }
            nbits = num_full_chunks; // Clear these bits at higher level
        }

        MultilevelBitmapFrameAllocator {
            bitmap_virt_addr,
            nframes,
            nlevels,
            frame_phys_addr: PhysAddr::new(start_addr),
            frame_stack: [0; FRAME_ALLOCATOR_STACK_SIZE],
            frame_stack_number: 0
        }
    }

    /// Allocate a frame, returning the frame number in this
    /// allocation region.
    fn fetch_frame(&mut self) -> Option<u64> {
        if self.frame_stack_number == 0 {
            // Empty stack => Find more frames

            let mut chunk_number: u64 = 0;
            for level in (1..self.nlevels).rev() {
                let ptr = self.bitmap_virt_addr[level].as_ptr() as *const u32;
                let bitmap = unsafe{*(ptr.offset(chunk_number as isize))};
                if bitmap == 0 {
                    return None; // Out of memory
                }
                chunk_number = chunk_number * 32
                    + nonzero_bit_index(bitmap) as u64;
            }

            // Get bitmap containing frame indices
            let ptr = unsafe{(self.bitmap_virt_addr[0].as_mut_ptr() as *mut u32).offset(chunk_number as isize)};
            let mut bitmap = unsafe{*ptr};

            // Take all frames and put them on the stack
            while bitmap != 0 {
                let index = nonzero_bit_index(bitmap);
                let frame_number = chunk_number * 32 + index as u64;
                bitmap ^= 1 << index;
                self.frame_stack[self.frame_stack_number] = frame_number;
                self.frame_stack_number += 1;
            }
            unsafe {core::ptr::write(ptr, 0)}; // Chunk now empty

            // Clear higher bitmaps if the chunk is empty
            for level in 1..self.nlevels {
                // Low 5 bits of the chunk at the lower level are the index at this level
                let index = chunk_number & 31;
                // High bits are the chunk at this level
                chunk_number = chunk_number >> 5;

                let ptr = unsafe{(self.bitmap_virt_addr[level].as_mut_ptr() as *mut u32)
                                 .offset(chunk_number as isize)};
                let mut bitmap = unsafe{*ptr};

                bitmap &= !(1 << index); // clear bit
                unsafe {core::ptr::write(ptr, bitmap)};

                if bitmap != 0 {
                    // This chunk still has frames => stop clearing
                    break;
                }
            }
        }
        if self.frame_stack_number == 0 {
            panic!("Stack still empty!") // bug!
        }
        // Stack now contains frames
        self.frame_stack_number -= 1;
        Some(self.frame_stack[self.frame_stack_number])
    }

    /// Put a frame back into the bitmap
    ///
    /// Input is the frame number returned by fetch_frame, not
    /// a physical address
    fn return_frame(&mut self, frame_number: u64) {
        if self.frame_stack_number < FRAME_ALLOCATOR_STACK_SIZE {
            self.frame_stack[self.frame_stack_number] = frame_number;
            self.frame_stack_number += 1;
            return;
        }

        // Calculate indices
        let mut chunk_number = frame_number;
        for level in 0..self.nlevels {
            let ptr = unsafe{(self.bitmap_virt_addr[level].as_mut_ptr() as *mut u32)
                             .offset(chunk_number as isize)};
            let bitmap_was_empty = unsafe{*ptr} == 0;
            let index = chunk_number & 31; // Low 5 bits are the index

            // Set bit
            unsafe{*ptr |= 1 << index;}

            if !bitmap_was_empty {
                // No need to change higher bitmaps
                break;
            }
            // Divide by 32 to get chunk number of higher level
            chunk_number = chunk_number >> 5;
        }
    }

    fn deallocate_frame(&mut self, frame: PhysFrame) {
        let frame_number = (frame.start_address() - self.frame_phys_addr) / 4096;
        self.return_frame(frame_number);
    }

    /// Allocate a consecutive set of frames
    ///
    /// num_frames    The number of frames required
    /// max_address   The maximum physical address in the set
    ///               e.g. for 32-bit addresses 0xFFFF_FFFF
    ///
    /// Returns the number of the first frame, or None
    /// if a set could not be found.
    ///
    /// Brute force search of lowest level bitmap. This is not
    /// very efficient, and is not intended to be called in
    /// performance-critical code.
    fn consecutive_frames(
        &mut self,
        needed_frames: u64,
        max_address: u64
    ) -> Option<u64> {
        // Ensure that there is at least one frame in range
        if max_address < (self.frame_phys_addr.as_u64() + 4095) {
            return None;
        }

        // Restrict the number of frames to those under the address limit
        let max_frames = (max_address + 1 - self.frame_phys_addr.as_u64()) >> 12;
        let nframes = if max_frames < self.nframes {max_frames} else {self.nframes};

        // Number of 32-bit chunks to search
        let nchunks = (self.nframes >> 5) + if self.nframes & 31 != 0 {1} else {0};

        // Pointer to lowest level frame bitmap
        let ptr = self.bitmap_virt_addr[0].as_mut_ptr() as *mut u32;

        let mut count = 0; // How many consecutive frames found so far?
        for chunk in 0..nchunks {
            let bitmap = unsafe{*ptr.offset(chunk as isize)};

            for pos in 0..32 {
                if bitmap & (1 << pos) == 0 {
                    // Not available
                    count = 0;
                } else {
                    // Available frame
                    count += 1;
                    if count == needed_frames {
                        // Found a consecutive set of frames
                        let start_frame = (chunk << 5) + pos + 1 - count;

                        // Mark each frame as taken
                        for frame in start_frame..(start_frame + needed_frames) {
                            let mut chunk_number = frame;

                            // Clear higher bitmaps if the chunk is empty
                            for level in 1..self.nlevels {
                                // Low 5 bits of the chunk at the lower level are the index at this level
                                let index = chunk_number & 31;
                                // High bits are the chunk at this level
                                chunk_number = chunk_number >> 5;

                                let ptr = unsafe{(self.bitmap_virt_addr[level].as_mut_ptr() as *mut u32)
                                                 .offset(chunk_number as isize)};
                                let mut bitmap = unsafe{*ptr};

                                bitmap &= !(1 << index); // clear bit
                                unsafe {core::ptr::write(ptr, bitmap)};

                                if bitmap != 0 {
                                    // This chunk still has frames => stop clearing
                                    break;
                                }
                            }
                        }
                        return Some(start_frame);
                    }
                }
            }
        }
        // Not found
        None
    }

    /// Allocate a set of consecutive frames
    fn allocate_consecutive_frames(
        &mut self,
        needed_frames: u64,
        max_address: u64
    ) -> Option<PhysFrame> {
        if let Some(frame_number) = self.consecutive_frames(needed_frames, max_address) {
            // Convert from frame number to physical address
            return PhysFrame::from_start_address(
                self.frame_phys_addr + frame_number * 4096).ok();
        }
        None
    }
}

unsafe impl FrameAllocator<Size4KiB> for MultilevelBitmapFrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame> {
        if let Some(frame_number) = self.fetch_frame() {
            // Convert from frame number to physical address
            return PhysFrame::from_start_address(
                self.frame_phys_addr + frame_number * 4096).ok();
        }
        None
    }
}

#[test_case]
fn test_two_frames() {
    let memory_info = unsafe {MEMORY_INFO.as_mut().unwrap()};
    let mut alloc = &mut memory_info.frame_allocator;

    let frame1 = alloc.fetch_frame();
    let frame2 = alloc.fetch_frame();

    assert!(frame1 != frame2);
}

#[test_case]
fn test_level2_cleared() {
    let memory_info = unsafe {MEMORY_INFO.as_mut().unwrap()};
    let mut alloc = &mut memory_info.frame_allocator;

    let frame1 = alloc.fetch_frame();
    // Move to next level-1 frame
    for i in 0..32 {
        alloc.allocate_frame();
    }
    let frame2 = alloc.fetch_frame();
    assert!(frame1 != frame2);
}

#[test_case]
fn test_quick_return() {
    let memory_info = unsafe {MEMORY_INFO.as_mut().unwrap()};
    let mut alloc = &mut memory_info.frame_allocator;

    let frame1 = alloc.fetch_frame();
    alloc.return_frame(frame1);
    let frame2 = alloc.fetch_frame();

    assert!(frame1 == frame2);
}

pub fn tryout() {
    let memory_info = unsafe {MEMORY_INFO.as_mut().unwrap()};
    let mut alloc = &mut memory_info.frame_allocator;

    const N: usize = 800;
    let count1 = time_stamp_counter();

    for i in 0..10 {
        // Allocate frames
        let frames = [0; N].map(|_| alloc.fetch_frame().unwrap());
        // Free them all again
        for f in frames {
            alloc.return_frame(f);
        }
    }
    let count2 = time_stamp_counter();
    println!("Clock ticks: {} M", (count2 - count1) / 1000000);
}
