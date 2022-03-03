
use x86_64::{
    structures::paging::{PageTable, PhysFrame, Size4KiB, FrameAllocator, OffsetPageTable},
    PhysAddr, VirtAddr
};

use crate::println;
use crate::allocator;
use bootloader::BootInfo;

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

        let phys_memory_offset = VirtAddr::new(boot_info.physical_memory_offset);

        let level_4_table = unsafe {active_level_4_table(phys_memory_offset)};

        // Initialise the memory mapper
        let mut mapper = unsafe {OffsetPageTable::new(level_4_table, phys_memory_offset)};
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
