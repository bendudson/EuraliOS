
use x86_64::{
    structures::paging::{Page, PageTable, PhysFrame, Size4KiB, FrameAllocator, OffsetPageTable, mapper::MapToError, PageTableFlags, Mapper
    },
    PhysAddr, VirtAddr
};

/// The level 4, 3 and 2 page table index
/// to access the level 1 page where stacks are stored
const THREAD_STACK_PAGE_INDEX: [u8; 3] = [5, 0, 0];

use crate::println;
use crate::allocator;
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
            //  [n * 8 + 1] -> User stack
            //      ...
            //  [n * 8 + 7] -> User stack

            for j in 1..8 {
                // Allocate user stack frames
                let entry = &mut table[n * 8 + j];

                let frame = memory_info.frame_allocator.allocate_frame()
                    .ok_or("Failed to allocate frame")?;

                entry.set_addr(frame.start_address(),
                               PageTableFlags::PRESENT |
                               PageTableFlags::WRITABLE |
                               PageTableFlags::USER_ACCESSIBLE);
            }

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

/// An allocator which uses bitmaps to keep track of available frames
///
/// 32 level-1 bitmaps, with one bit per frame
/// 1  level-2 bitmap, one bit per level-1 bitmap
///
pub struct MultilevelBitmapFrameAllocator {
    /// Virtual address of the first level 2 entry
    /// Each entry is 32 bits long, one bit per level 1 entry
    level_2_virt_addr: VirtAddr,

    /// Virtual address of the first level 1 entry
    /// Each entry is 32 bits long, one bit per frame
    level_1_virt_addr: VirtAddr,

    /// Physical start address of the frames
    frame_phys_addr: PhysAddr,

    /// Stack of up to 32 frames
    frame_stack: [u64; 32],
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

        println!("Region: {:#016X} - {:#016X}", start_addr, end_addr);
        println!("Number of frames: {}", nframes);

        // Use the first frame for bitmaps
        let level_2_virt_addr = physical_memory_offset + start_addr;
        let level_1_virt_addr = level_2_virt_addr + 4u64;

        // Set level 2 page table values
        let level_2_ptr = level_2_virt_addr.as_mut_ptr() as *mut u32;
        *level_2_ptr = 0xFFFF_FFFF; // All have some frames

        // Set level 1 page table values
        let level_1_ptr = level_1_virt_addr.as_mut_ptr() as *mut u32;
        *level_1_ptr = 0xFFFF_FFFE; // Clear first bit
        for i in 1..32 {
            *(level_1_ptr.offset(i)) = 0xFFFF_FFFF;
        }

        MultilevelBitmapFrameAllocator {
            level_2_virt_addr,
            level_1_virt_addr,
            frame_phys_addr: PhysAddr::new(start_addr),
            frame_stack: [0; 32],
            frame_stack_number: 0
        }
    }

    /// Allocate a frane, returning the frame number in this
    /// allocation region.
    fn fetch_frame(&mut self) -> u64 {
        if self.frame_stack_number == 0 {
            // Empty stack => Find more frames

            let l2_ptr = self.level_2_virt_addr.as_mut_ptr() as *mut u32;
            let l2_bitmap = unsafe{*l2_ptr};

            if l2_bitmap == 0 {
                panic!("Out of memory!")
            }

            let l2_index = nonzero_bit_index(l2_bitmap);

            let l1_ptr = unsafe{(self.level_1_virt_addr.as_mut_ptr() as *mut u32)
                                .offset(l2_index as isize)};
            let mut l1_bitmap = unsafe{*l1_ptr};

            // Take all frames and put them on the stack
            while l1_bitmap != 0 {
                let l1_index = nonzero_bit_index(l1_bitmap);
                let frame_number =
                    (l2_index as u64) * 32u64 +
                    (l1_index as u64);
                l1_bitmap ^= 1 << l1_index;
                self.frame_stack[self.frame_stack_number] = frame_number;
                self.frame_stack_number += 1;
            }

            unsafe{*l1_ptr = 0}
            // None left in this level 1 bitmap -> clear level 2 bit
            unsafe{*l2_ptr &= !(1 << l2_index)};

        }

        if self.frame_stack_number == 0 {
            panic!("Stack still empty!")
        }
        // Stack now contains frames
        self.frame_stack_number -= 1;
        self.frame_stack[self.frame_stack_number]
    }

    /// Put a frame back into the bitmap
    ///
    /// Input is the frame number returned by fetch_frame, not
    /// a physical address
    fn return_frame(&mut self, frame_number: u64) {
        if self.frame_stack_number < 32 {
            self.frame_stack[self.frame_stack_number] = frame_number;
            self.frame_stack_number += 1;
            return;
        }
        // Calculate indices
        let l1_index = frame_number % 32;
        let l2_index = frame_number >> 5;

        let l1_ptr = unsafe{(self.level_1_virt_addr.as_mut_ptr() as *mut u32)
                            .offset(l2_index as isize)};
        unsafe{*l1_ptr |= 1 << l1_index;}

        // set level 2 bit
        let l2_ptr = self.level_2_virt_addr.as_mut_ptr() as *mut u32;
        unsafe{*l2_ptr |= 1 << l2_index};
    }

    fn deallocate_frame(&mut self, frame: PhysFrame) {
        let frame_number = (frame.start_address() - self.frame_phys_addr) / 4096;
        self.return_frame(frame_number);
    }
}

unsafe impl FrameAllocator<Size4KiB> for MultilevelBitmapFrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame> {
        let frame_number = self.fetch_frame();

        // Convert from frame number to physical address
        PhysFrame::from_start_address(
            self.frame_phys_addr + frame_number * 4096).ok()
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
        let frames = [0; N].map(|_| alloc.fetch_frame());
        // Free them all again
        for f in frames {
            alloc.return_frame(f);
        }
    }
    let count2 = time_stamp_counter();
    println!("Clock ticks: {} M", (count2 - count1) / 1000000);
}
