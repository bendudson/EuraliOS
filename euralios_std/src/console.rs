///! Definitions and routines for handling consoles

pub mod sequences {
    pub const F1: u64 = 0x1b_9b_31_31_7e; // ESC [ 1 1 ~
    pub const F2: u64 = 0x1b_9b_31_32_7e; // ESC [ 1 2 ~
    pub const F3: u64 = 0x1b_9b_31_33_7e; // ESC [ 1 3 ~
    pub const F4: u64 = 0x1b_9b_31_34_7e; // ESC [ 1 4 ~
    pub const F5: u64 = 0x1b_9b_31_35_7e; // ESC [ 1 5 ~
    pub const F6: u64 = 0x1b_9b_31_37_7e; // ESC [ 1 7 ~
    pub const F7: u64 = 0x1b_9b_31_38_7e; // ESC [ 1 8 ~
    pub const F8: u64 = 0x1b_9b_31_39_7e; // ESC [ 1 9 ~
    pub const F9: u64 = 0x1b_9b_32_30_7e; // ESC [ 2 0 ~
    pub const F10: u64 = 0x1b_9b_32_31_7e; // ESC [ 2 1 ~
    pub const F11: u64 = 0x1b_9b_32_33_7e; // ESC [ 2 3 ~
    pub const F12: u64 = 0x1b_9b_32_34_7e; // ESC [ 3 4 ~
}
