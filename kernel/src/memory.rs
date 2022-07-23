
mod frame_allocator; // In memory/frame_allocator.rs
use frame_allocator::MultilevelBitmapFrameAllocator;
mod allocator;
pub mod kernel_info;

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

        kernel_info::init(&mut frame_allocator, physical_memory_offset)
            .expect("KernelInfo initialization failed");

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
/// - Copies the kernel pagetables into a new set of tables
/// - Adds the KernelInfo read-only page
///
/// Returns
/// -------
///
/// - A pointer to the PageTable (virtual address in kernel mapped pages)
/// - The physical address which can be written to cr3
///
pub fn create_new_user_pagetable() -> (*mut PageTable, u64) {
    let memory_info = unsafe {MEMORY_INFO.as_mut().unwrap()};

    // Copy kernel pages
    let (user_page_table_ptr, user_page_table_physaddr) =
        copy_pagetables(memory_info.kernel_l4_table);

    // Add KernelInfo page
    let memory_info = unsafe {MEMORY_INFO.as_mut().unwrap()};
    let mut mapper = unsafe {
        OffsetPageTable::new(&mut *user_page_table_ptr,
                             memory_info.physical_memory_offset)};
    kernel_info::add_to_user_table(&mut mapper,
                                   &mut memory_info.frame_allocator);

    (user_page_table_ptr, user_page_table_physaddr)
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
///
/// Inputs
/// ------
///   size   Size of memory region in bytes
///
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
                            PageTableFlags::USER_ACCESSIBLE)
            .map_err(|_| MapToError::FrameAllocationFailed)?;
    }

    Ok(())
}

/// Map a consecutive set of pages to a consecutive set of frames
///
/// level_4_physaddr  The physical address of the L4 pagetable
/// start_page      First page in the sequence
/// start_frame     First frame in the sequence
/// num_frames      Number of consecutive frames
fn map_consecutive_pages(
    level_4_physaddr: u64,
    start_page: Page,
    start_frame: PhysFrame,
    num_frames: u64)
    -> Result<PhysAddr, MapToError<Size4KiB>> {

    let frame_range = PhysFrame::range(start_frame, start_frame + num_frames);
    let page_range = Page::range(start_page, start_page + num_frames);

    let memory_info = unsafe {MEMORY_INFO.as_mut().unwrap()};

    let l4_table: &mut PageTable = unsafe {
        &mut *(memory_info.physical_memory_offset
               + level_4_physaddr).as_mut_ptr()};

    let frame_allocator = &mut memory_info.frame_allocator;

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

    // Try to allocate a consecutive set of frames
    let start_frame = {
        let memory_info = unsafe {MEMORY_INFO.as_mut().unwrap()};
        let frame_allocator = &mut memory_info.frame_allocator;

        frame_allocator
            .allocate_consecutive_frames(num_frames, max_physaddr)
            .ok_or(MapToError::FrameAllocationFailed)?
    };

    let start_page = Page::containing_address(start_addr);

    map_consecutive_pages(level_4_physaddr,
                          start_page,
                          start_frame,
                          num_frames)
}

/// Create a mapping to a specific range of physical memory
///
/// Doesn't do any frame allocation, so assumes that it's ok
/// to use the memory. Used for mapping a memory chunk to
/// VGA memory.
pub fn create_physical_range_pages(
    level_4_physaddr: u64,
    start_virtaddr: VirtAddr,
    num_frames: u64,
    start_physaddr: PhysAddr)
    -> Result<PhysAddr, MapToError<Size4KiB>> {

    let start_page = Page::from_start_address(start_virtaddr)
        .map_err(|_| MapToError::FrameAllocationFailed)?;
    let start_frame = PhysFrame::from_start_address(start_physaddr)
        .map_err(|_| MapToError::FrameAllocationFailed)?;

    map_consecutive_pages(level_4_physaddr,
                          start_page,
                          start_frame,
                          num_frames)
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

    // Remove from page table, get address of l3 entry
    let (physaddr, level) = get_page_chunk(level_4_physaddr, address, true)?;

    // Free page tables and pages recursively
    free_pages_rec(memory_info.physical_memory_offset,
                   &mut memory_info.frame_allocator,
                   physaddr,
                   level); // Page table level
    Ok(())
}

/// Remove a page chunk from a page table
/// Doesn't free any of the pages
///
/// Returns physical address and level of the page table that it points to
pub fn get_page_chunk(
    level_4_physaddr: u64,
    address: VirtAddr,
    take: bool
) -> Result<(PhysAddr, u16), usize> {
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

    let physaddr = l3_entry.addr();

    if take {
        // Mark entry as empty
        l3_entry.set_unused();
    }

    // Return address of level 2 page table
    Ok((physaddr, 2))
}

/// Finds an available page chunk entry, stores the physical address
/// in the page table and returns the virtual address.
pub fn put_page_chunk(
    level_4_physaddr: u64,
    physaddr: PhysAddr
) -> Result<VirtAddr, usize> {
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
    let l3_table: &mut PageTable = unsafe {
        &mut *(memory_info.physical_memory_offset
               + l4_entry.addr().as_u64()).as_mut_ptr()};

    // Each entry in l3_table from FIRST to LAST inclusive
    // is a separate chunk
    for ind in MEMORY_CHUNK_L3_FIRST..=MEMORY_CHUNK_L3_LAST {
        let entry = &mut l3_table[ind];
        if entry.is_unused() {
            // Found an empty chunk
            entry.set_addr(physaddr,
                           PageTableFlags::PRESENT |
                           PageTableFlags::WRITABLE |
                           PageTableFlags::USER_ACCESSIBLE);

            // Convert L4 and L3 index into virtual address
            return Ok(VirtAddr::new(((MEMORY_CHUNK_L4_ENTRY as u64) << 39) |
                                    (ind << 30) as u64));
        }
    }
    Err(syscalls::SYSCALL_ERROR_NOMEMSLOTS)
}

///////////////////////////////////////////////////////////////////////

/// Recursively free all pages and page tables, including the page
/// table at the given table_physaddr.
fn free_pages_rec(physical_memory_offset: VirtAddr,
                  frame_allocator: &mut MultilevelBitmapFrameAllocator,
                  physaddr: PhysAddr,
                  level: u16) {

    if level == 0 {
        // A frame, not a table
        frame_allocator.deallocate_frame(
            PhysFrame::containing_address(physaddr));
        return;
    }

    let table = unsafe{&mut *(physical_memory_offset
                              + physaddr.as_u64())
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
        PhysFrame::from_start_address(physaddr).unwrap());
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
