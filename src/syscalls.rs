
use core::arch::asm;

// register for address of syscall handler
const MSR_STAR: usize = 0xc0000081;
const MSR_LSTAR: usize = 0xc0000082;
const MSR_FMASK: usize = 0xc0000084;

/// Set up syscall handler
///
/// Note: This depends on the order of the GDT table
///
/// https://nfil.dev/kernel/rust/coding/rust-kernel-to-userspace-and-back/
pub fn init() {
    let handler_addr = handle_syscall as *const () as u64;
    unsafe {
        // Enable System Call Extensions (SCE) to be able to use the
        // syscall/sysret opcodes by setting the last bit in the MSR
        // IA32_EFER
        asm!("mov ecx, 0xC0000080",
             "rdmsr",
             "or eax, 1",
             "wrmsr");

        // clear Interrupt flag on syscall with AMD's MSR_FSTAR register
        asm!("xor rdx, rdx",
             "mov rax, 0x200",
             "wrmsr",
             in("rcx") MSR_FMASK);
        // write handler address to AMD's MSR_LSTAR register
        asm!("mov rdx, rax",
             "shr rdx, 32",
             "wrmsr",
             in("rax") handler_addr,
             in("rcx") MSR_LSTAR);
        // write segments to use on syscall/sysret to AMD'S MSR_STAR register
        asm!(
            "xor rax, rax",
            "mov rdx, 0x230008", // use seg selectors 8, 16 for syscall and 43, 51 for sysret
            "wrmsr",
            in("rcx") MSR_STAR);
    }
}

#[naked]
fn handle_syscall() {
    unsafe {
        asm!("nop",
             "nop",
             "nop",
             "sysretq",
             options(noreturn));
    }
}

