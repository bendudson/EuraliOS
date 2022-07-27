//! Multi-level bitmap frame allocator

use core::arch::asm;

use bootloader::bootinfo::MemoryMap;
use bootloader::bootinfo::MemoryRegionType;
use x86_64::{
    structures::paging::{PhysFrame,
                         Size4KiB,
                         FrameAllocator},
    PhysAddr, VirtAddr
};

use crate::println;

/// Return the index of a non-zero bit
///
/// Uses the BSF instruction: <https://www.felixcloutier.com/x86/bsf>
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

    pub fn deallocate_frame(&mut self, frame: PhysFrame) {
        if frame.start_address() < self.frame_phys_addr {
            // Not managed by this frame allocator
            return;
        }
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
        let nchunks = (nframes >> 5) + if nframes & 31 != 0 {1} else {0};

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
                            for level in 0..self.nlevels {
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
    pub fn allocate_consecutive_frames(
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
