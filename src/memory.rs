
use x86_64::{
    structures::paging::{Page, PageTable, PhysFrame, Size4KiB, FrameAllocator, OffsetPageTable, mapper::MapToError, PageTableFlags, Mapper
    },
    PhysAddr, VirtAddr
};

use crate::println;
use crate::allocator;
use bootloader::BootInfo;

struct MemoryInfo {
    boot_info: &'static BootInfo,

    physical_memory_offset: VirtAddr,

    /// Allocate empty frames
    frame_allocator: BootInfoFrameAllocator
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
    use x86_64::{structures::paging::Translate}; // provides translate_addr

    interrupts::without_interrupts(|| {
        let mut memory_size = 0;
        for region in boot_info.memory_map.iter() {
            let start_addr = region.range.start_addr();
            let end_addr = region.range.end_addr();
            memory_size += end_addr - start_addr;
            println!("MEM [{:#016X}-{:#016X}] {:?}\n", start_addr, end_addr, region.region_type);
        }
        println!("Memory size: {} KB\n", memory_size >> 10);

        let physical_memory_offset = VirtAddr::new(boot_info.physical_memory_offset);

        let level_4_table = unsafe {active_level_4_table(physical_memory_offset)};

        for (i, entry) in level_4_table.iter().enumerate() {
            if !entry.is_unused() {
                println!("L4 Entry {}: {:?}", i, entry);
            }
        }

        // Initialise the memory mapper
        let mut mapper = unsafe {OffsetPageTable::new(level_4_table, physical_memory_offset)};
        let mut frame_allocator = unsafe {
            BootInfoFrameAllocator::init(&boot_info.memory_map)
        };

        let addresses = [
            // the identity-mapped vga buffer page
            0xb8000,
            // some code page
            0x201008,
            // some stack page
            0x0100_0020_1a10,
            // virtual address mapped to physical address 0
            boot_info.physical_memory_offset,
        ];

        for &address in &addresses {
            let virt = VirtAddr::new(address);
            // new: use the `mapper.translate_addr` method
            let phys = mapper.translate_addr(virt);
            println!("{:?} -> {:?}", virt, phys);
        }

        allocator::init_heap(&mut mapper, &mut frame_allocator)
            .expect("heap initialization failed");

        // Store boot_info for later calls
        unsafe { MEMORY_INFO = Some(MemoryInfo {
            boot_info,
            physical_memory_offset,
            frame_allocator
        }) };
    });
}

/// Create a new page table
///
pub fn create_user_pagetable() -> *mut PageTable {
    // Need to borrow as mutable so that we can allocate new frames
    // and so modify the frame allocator
    let memory_info = unsafe {MEMORY_INFO.as_mut().unwrap()};

    // Get a frame to store the level 4 frame
    let level_4_table_frame = memory_info.frame_allocator.allocate_frame().unwrap();
    let phys = level_4_table_frame.start_address(); // Physical address
    let virt = memory_info.physical_memory_offset + phys.as_u64(); // Kernel virtual address
    let page_table_ptr: *mut PageTable = virt.as_mut_ptr();

    // Clear all entries
    unsafe {
        (*page_table_ptr).zero();
    }

    page_table_ptr
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
// Routines to allocate the same memory frames in two page tables

/// Allocate memory, and map to virtual addresses in two page tables
///
pub fn allocate_two_pages_mappers(
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
    mapper1: &mut impl Mapper<Size4KiB>,
    start_addr1: VirtAddr,
    size: u64,
    flags1: PageTableFlags,
    mapper2: &mut impl Mapper<Size4KiB>,
    start_addr2: VirtAddr,
    flags2: PageTableFlags)
    -> Result<(), MapToError<Size4KiB>> {

    let page_range1 = {
        let end_addr1 = start_addr1 + size - 1u64;
        let start_page = Page::containing_address(start_addr1);
        let end_page = Page::containing_address(end_addr1);
        Page::range_inclusive(start_page, end_page)
    };

    let page_range2 = {
        let end_addr2 = start_addr2 + size - 1u64;
        let start_page = Page::containing_address(start_addr2);
        let end_page = Page::containing_address(end_addr2);
        Page::range_inclusive(start_page, end_page)
    };

    for (page1, page2) in page_range1.zip(page_range2) {
        let frame = frame_allocator
            .allocate_frame()
            .ok_or(MapToError::FrameAllocationFailed)?;
        unsafe {
            // Map both pages to the same frame
            mapper1.map_to(page1,
                           frame,
                           flags1,
                           frame_allocator)?.flush();
            mapper2.map_to(page2,
                           frame,
                           flags2,
                           frame_allocator)?.flush()
        };
    }

    Ok(())
}

pub fn allocate_two_pages(
    // First table
    level_4_table1: *mut PageTable,
    start_addr1: VirtAddr,
    size: u64,
    flags1: PageTableFlags,
    level_4_table2: *mut PageTable,
    start_addr2: VirtAddr,
    flags2: PageTableFlags)
    -> Result<(), MapToError<Size4KiB>> {

    let memory_info = unsafe {MEMORY_INFO.as_mut().unwrap()};

    let mut mapper1 = unsafe {
        OffsetPageTable::new(&mut *level_4_table1,
                             memory_info.physical_memory_offset)};
    let mut mapper2 = unsafe {
        OffsetPageTable::new(&mut *level_4_table2,
                             memory_info.physical_memory_offset)};

    allocate_two_pages_mappers(
        &mut memory_info.frame_allocator,
        &mut mapper1,
        start_addr1, size, flags1,
        &mut mapper2,
        start_addr2, flags2)
}

use bootloader::bootinfo::MemoryMap;
use bootloader::bootinfo::MemoryRegionType;

/// A FrameAllocator that returns usable frames from the bootloader's memory map.
pub struct BootInfoFrameAllocator {
    memory_map: &'static MemoryMap,
    next: usize,
}

impl BootInfoFrameAllocator {
    /// Create a FrameAllocator from the passed memory map.
    ///
    /// This function is unsafe because the caller must guarantee that the passed
    /// memory map is valid. The main requirement is that all frames that are marked
    /// as `USABLE` in it are really unused.
    pub unsafe fn init(memory_map: &'static MemoryMap) -> Self {
        BootInfoFrameAllocator {
            memory_map,
            next: 0,
        }
    }

    /// Returns an iterator over the usable frames specified in the memory map.
    fn usable_frames(&self) -> impl Iterator<Item = PhysFrame> {
        // get usable regions from memory map
        let regions = self.memory_map.iter();
        let usable_regions = regions
            .filter(|r| r.region_type == MemoryRegionType::Usable);
        // map each region to its address range
        let addr_ranges = usable_regions
            .map(|r| r.range.start_addr()..r.range.end_addr());
        // transform to an iterator of frame start addresses
        let frame_addresses = addr_ranges.flat_map(|r| r.step_by(4096));
        // create `PhysFrame` types from the start addresses
        frame_addresses.map(|addr| PhysFrame::containing_address(PhysAddr::new(addr)))
    }
}

unsafe impl FrameAllocator<Size4KiB> for BootInfoFrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame> {
        let frame = self.usable_frames().nth(self.next);
        self.next += 1;
        frame
    }
}
