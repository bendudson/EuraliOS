
use core::arch::asm;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::memory;

/// The Programmable Interrupt Timer frequency divider
const PIT_TICKS_PER_INTERRUPT: u64 = 65536;

/// Cumulative number of PIT ticks since start
static PIT_TICKS: AtomicU64 = AtomicU64::new(0);

/// Previous value of Time Stamp Counter
static LAST_TSC: AtomicU64 = AtomicU64::new(0);

static TSC_PER_PIT: AtomicU64 = AtomicU64::new(0);

/// Read the processor's Time Stamp Counter
/// uses RDTSC
/// <https://www.felixcloutier.com/x86/rdtsc>
fn time_stamp_counter() -> u64 {
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

/// This function is called by the timer interrupt handler
pub fn pit_interrupt_notify() { 
    // Increment the number of PIT ticks
    PIT_TICKS.fetch_add(PIT_TICKS_PER_INTERRUPT, Ordering::Relaxed);

    // Get the change in TSC from last time, and update moving average of
    // TSC ticks per PIT tick.
    let new_tsc = time_stamp_counter();
    let last_tsc = LAST_TSC.swap(new_tsc, Ordering::Relaxed);
    let new_tsc_per_pit = (new_tsc - last_tsc) / PIT_TICKS_PER_INTERRUPT;
    let ma_tsc_per_pit = (new_tsc_per_pit + TSC_PER_PIT.load(Ordering::Relaxed)) / 2;
    TSC_PER_PIT.store(ma_tsc_per_pit, Ordering::Relaxed);

    // Store in user-accessible KernelInfo page
    let info = memory::kernel_info::get_mut();
    info.pit_ticks = PIT_TICKS.load(Ordering::Relaxed);
    info.last_tsc = new_tsc;
    info.tsc_per_pit = ma_tsc_per_pit;
}

/// Monotonic count of he number of microseconds since restart
///
/// Uses PIT interrupts to calibrate the TSC
/// 
pub fn microseconds_monotonic() -> u64 {
    // Number of PIT ticks
    let pit = PIT_TICKS.load(Ordering::Relaxed);
    // Number of TSC ticks since last PIT interrupt
    let tsc = time_stamp_counter() - LAST_TSC.load(Ordering::Relaxed);

    // Number of TSC counts per PIT tick
    let tsc_per_pit = TSC_PER_PIT.load(Ordering::Relaxed);

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
