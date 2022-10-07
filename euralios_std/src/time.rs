use core::arch::asm;

pub use core::time::Duration;

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

/// This structure is mapped read-only into user address space
pub struct KernelInfo {
    pub pit_ticks: u64, // Number of PIT ticks since restart
    pub last_tsc: u64, // TSC value at last pit_ticks update
    pub tsc_per_pit: u64, // Change in TSC ticks per PIT tick
}

/// The virtual address of the KernelInfo struct
const KERNELINFO_VIRTADDR: u64 = 0x4fff000;

/// Get a reference to the KernelInfo struct
pub fn kernel_info() -> &'static KernelInfo {
    let ptr = KERNELINFO_VIRTADDR as *const KernelInfo;
    unsafe{&(*ptr)}
}

/// Monotonic count of he number of microseconds since restart
///
/// Uses PIT interrupts to calibrate the TSC. Calibration calculated
/// by the kernel and stored in the KernelInfo struct.
///
pub fn microseconds_monotonic() -> u64 {
    // Calibration calculated in the kernel (kernel/src/time.rs)
    let info = kernel_info();

    // Number of PIT ticks
    let pit = info.pit_ticks;
    // Number of TSC ticks since last PIT interrupt
    let tsc = time_stamp_counter() - info.last_tsc;

    // Number of TSC counts per PIT tick
    let tsc_per_pit = info.tsc_per_pit;

    // PIT frequency is 3_579_545 / 3 = 1_193_181.666 Hz
    //                   each PIT tick is 0.83809534452 microseconds
    //             878807 / (1024*1024) = 0.83809566497
    //
    // Calculate total TSC then divide to get microseconds
    // Note: Don't use TSC directly because jitter in tsc_per_pit would lead to
    // non-monotonic outputs

    // Note! This next expression will overflow in about 2 hours :
    //       2**64 / (1024 * 1024 * 2270) microseconds
    //((pit * tsc_per_pit + tsc) * 878807) / (1024*1024 * tsc_per_pit)

    const SCALED_TSC_RATE: u64 = 16;
    let scaled_tsc = (tsc * SCALED_TSC_RATE) / tsc_per_pit;

    // Factorize 878807 = 437 * 2011
    // This will overflow in about 142 years : 2**64 / 4096 microseconds
    ((((pit * SCALED_TSC_RATE + scaled_tsc) * 2011) / 4096) * 437) / (256 * SCALED_TSC_RATE)
}
