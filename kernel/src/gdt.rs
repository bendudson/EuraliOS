use x86_64::VirtAddr;
use x86_64::structures::tss::TaskStateSegment;

use spin::Mutex;
use lazy_static::lazy_static;

/// Fixed kernel stack which is the same for all processes.  Index 0
/// should only be used for interrupts which won't switch contexts
pub const DOUBLE_FAULT_IST_INDEX: u16 = 0;
pub const PAGE_FAULT_IST_INDEX: u16 = 0;
pub const GENERAL_PROTECTION_FAULT_IST_INDEX: u16 = 0;

/// Used by timer interrupt and syscall to set kernel stack
///
/// Note: Syscalls must offset the stack location because
///       otherwise syscalls could not be interrupted.
pub const TIMER_INTERRUPT_INDEX: u16 = 1;
pub const KEYBOARD_INTERRUPT_INDEX: u16 = 1;

/// Use an interrupt stack table entry as temporary storage
/// for the user stack during a syscall.
pub const SYSCALL_TEMP_INDEX: u16 = 2;


lazy_static! {
    /// The Task State Segment (TSS)
    ///
    /// In x86-64 mode this contains:
    /// - The stack pointer addresses for each privilege level.
    /// - Pointer Addresses for the Interrupt Stack Table
    /// - Offset Address of the IO permission bitmap.
    ///
    /// The TSS is static but also mutable so we can change the stack pointers
    /// during task switching. To protect access to the TSS a spinlock is used.
    ///
    /// Notes:
    ///  - There can be up to 7 IST entries per CPU
    ///    https://www.kernel.org/doc/Documentation/x86/kernel-stacks
    ///
    static ref TSS: Mutex<TaskStateSegment> = {
        let mut tss = TaskStateSegment::new();
        tss.interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize] = {
            const STACK_SIZE: usize = 4096 * 5;
            static mut STACK: [u8; STACK_SIZE] = [0; STACK_SIZE];

            let stack_start = VirtAddr::from_ptr(unsafe { &STACK });
            let stack_end = stack_start + STACK_SIZE;
            stack_end
        };

        // Set initial timer interrupt index. This will be modified to set
        // the kernel stack for each thread. Those stacks will contain
        // the thread registers and flags.
        tss.interrupt_stack_table[TIMER_INTERRUPT_INDEX as usize] =
            tss.interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize];

        Mutex::new(tss)
    };
}

/// Function to extract a reference with static lifetime
///
/// Mutex lock returns a MutexGuard, which dereferences to a reference with
/// a lifetime tied to the mutex lock. This function casts the reference
/// to have 'static lifetime which Descriptor::tss_segment expects.
///
/// Note: Should not be used except in setting the TSS in the GDT
///
unsafe fn tss_reference() -> &'static TaskStateSegment {
    let tss_ptr = &*TSS.lock() as *const TaskStateSegment;
    & *tss_ptr
}

pub fn tss_address() -> u64 {
    let tss_ptr = &*TSS.lock() as *const TaskStateSegment;
    tss_ptr as u64
}

/// Set the interrupt stack table entry to a given virtual address
///
/// This is called to set the kernel stack of the current process
pub fn set_interrupt_stack_table(index: usize, stack_end: VirtAddr) {
    TSS.lock().interrupt_stack_table[index] = stack_end;
}

use x86_64::structures::gdt::{GlobalDescriptorTable, Descriptor, SegmentSelector};

lazy_static! {
    /// Set up the Global Descriptor Table the first time this is accessed
    /// This adapted from MOROS https://github.com/vinc/moros/blob/trunk/src/sys/gdt.rs#L37
    static ref GDT: (GlobalDescriptorTable, Selectors) = {
        let mut gdt = GlobalDescriptorTable::new();

        let tss = unsafe {tss_reference()};

        // Ring 0 segments for the kernel
        let code_selector = gdt.add_entry(Descriptor::kernel_code_segment());
        let data_selector = gdt.add_entry(Descriptor::kernel_data_segment());
        let tss_selector = gdt.add_entry(Descriptor::tss_segment(tss));
        // Ring 3 data and code segments for user code
        let user_data_selector = gdt.add_entry(Descriptor::user_data_segment());
        let user_code_selector = gdt.add_entry(Descriptor::user_code_segment());
        (gdt, Selectors { code_selector, data_selector, tss_selector,
                          user_code_selector, user_data_selector})
    };
}

struct Selectors {
    code_selector: SegmentSelector,
    data_selector: SegmentSelector,
    tss_selector: SegmentSelector,
    user_data_selector: SegmentSelector,
    user_code_selector: SegmentSelector
}

pub fn init() {
    use x86_64::instructions::segmentation::{Segment, CS, DS};
    use x86_64::instructions::tables::load_tss;

    GDT.0.load();
    unsafe {
        CS::set_reg(GDT.1.code_selector);
        DS::set_reg(GDT.1.data_selector);
        load_tss(GDT.1.tss_selector);
    }
}

pub fn get_kernel_segments() -> (SegmentSelector, SegmentSelector) {
    (GDT.1.code_selector, GDT.1.data_selector)
}

pub fn get_user_segments() -> (SegmentSelector, SegmentSelector) {
    (GDT.1.user_code_selector, GDT.1.user_data_selector)
}
