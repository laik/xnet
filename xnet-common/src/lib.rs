#![no_std]

#[repr(C)]
pub struct LogEvent {
    pub msg: [u8; 64],
}
