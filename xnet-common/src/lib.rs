#![no_std]

use bytemuck::{Pod, Zeroable};

// Use aya-ebpf for eBPF targets, aya for regular targets
#[cfg(feature = "aya-ebpf")]
pub use aya_ebpf;
#[cfg(feature = "aya")]
pub use aya;

#[repr(C)]
#[derive(Debug, Clone, Copy, Zeroable, Pod)]
pub struct LogEvent {
    pub msg: [u8; 64],
}

// 定义流量统计结构，供用户空间和内核空间共享
#[repr(C)]
#[derive(Debug, Clone, Copy, Zeroable, Pod)]
pub struct PortStats {
    pub packets: u64,
    pub bytes: u64,
    pub last_seen: u64,
}

// 定义设备流量统计结构，供用户空间和内核空间共享
#[repr(C)]
#[derive(Debug, Clone, Copy, Zeroable, Pod)]
pub struct DeviceStats {
    pub packets: u64,
    pub bytes: u64,
    pub last_seen: u64,
}

// Add aya::Pod implementation for PortStats when aya feature is enabled
#[cfg(feature = "aya")]
unsafe impl aya::Pod for PortStats {}

// Add aya::Pod implementation for DeviceStats when aya feature is enabled
#[cfg(feature = "aya")]
unsafe impl aya::Pod for DeviceStats {}

// 存储IP地址的静态缓冲区
static mut IP_BUFFER: [u8; 16] = [0; 16];

// 将整数IP地址转换为字符串,十进制表示
pub fn int_to_ip(ip: u32) -> &'static str {
    unsafe {
        let buf = &mut IP_BUFFER[..];
        let mut pos = 0;

        // 转换第一个字节
        pos += write_num(&mut buf[pos..], (ip >> 0) & 0xFF);
        buf[pos] = b'.';
        pos += 1;

        // 转换第二个字节
        pos += write_num(&mut buf[pos..], (ip >> 8) & 0xFF);
        buf[pos] = b'.';
        pos += 1;

        // 转换第三个字节
        pos += write_num(&mut buf[pos..], (ip >> 16) & 0xFF);
        buf[pos] = b'.';
        pos += 1;

        // 转换第四个字节
        pos += write_num(&mut buf[pos..], ip & 0xFF);

        // 将字节切片转换为&str
        core::str::from_utf8_unchecked(&buf[..pos])
    }
}

// 将0-255的数字写入缓冲区，返回写入的字节数
fn write_num(buf: &mut [u8], num: u32) -> usize {
    if num == 0 {
        buf[0] = b'0';
        return 1;
    }

    let mut n = num;
    let mut i = 0;
    let mut temp = [0; 3]; // 最大255，三位数字

    while n > 0 {
        temp[i] = (n % 10) as u8 + b'0';
        n /= 10;
        i += 1;
    }

    // 反转存储到缓冲区
    for j in 0..i {
        buf[j] = temp[i - 1 - j];
    }

    i
}

#[cfg(test)]
mod tests {}
