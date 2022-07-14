use core::arch::asm;

pub fn time_stamp_counter() -> u64 {
    let counter: u64;
    unsafe{
        asm!("rdtsc",
             "shl rdx, 32", // High bits in EDX
             "or rdx, rax", // Low bits in EAX
             out("rdx") counter,
             out("rax") _, // Clobbers RAX
             options(pure, nomem, nostack)
        );
    }
    counter
}
