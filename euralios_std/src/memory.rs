
extern crate alloc;
use linked_list_allocator::LockedHeap;

#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap::empty();

pub fn init(heap_start: usize, heap_size: usize) {
    unsafe {ALLOCATOR.lock().init(heap_start, heap_size);}
}

// Allocator error handler
#[alloc_error_handler]
fn alloc_error_handler(layout: alloc::alloc::Layout) -> ! {
    panic!("allocation error: {:?}", layout)
}
