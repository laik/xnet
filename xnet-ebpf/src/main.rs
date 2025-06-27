#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};
use aya_log_ebpf::info;

#[map]
static mut IP_STATS: HashMap<u32, u64> = HashMap::with_max_entries(1024, 0);

#[map]
static mut CONNECTION_TRACK: HashMap<u64, u32> = HashMap::with_max_entries(8192, 0);

#[map]
static mut CONNECTION_STATS: HashMap<u64, u64> = HashMap::with_max_entries(8192, 0);

#[xdp]
pub fn xnet(ctx: XdpContext) -> u32 {
    match try_xnet(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_PASS,
    }
}

fn try_xnet(ctx: XdpContext) -> Result<u32, ()> {
    let data = ctx.data();
    let data_end = ctx.data_end();

    // 以太网头部边界检查
    let eth_size = core::mem::size_of::<EthHdr>();
    if data + eth_size > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    // 安全访问以太网头部
    let ethhdr = data as *const EthHdr;
    let eth_proto = unsafe { (*ethhdr).eth_proto.to_be() };
    if eth_proto != 0x0800 {
        return Ok(xdp_action::XDP_PASS);
    }

    // IP头部边界检查
    let ip_offset = eth_size;
    let ip_size = core::mem::size_of::<IpHdr>();
    if data + ip_offset + ip_size > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    // 安全访问IP头部
    let iphdr = (data + ip_offset) as *const IpHdr;
    let src_ip = unsafe { (*iphdr).saddr };
    let dst_ip = unsafe { (*iphdr).daddr };
    let protocol = unsafe { (*iphdr).protocol };

    // 更新IP流量统计
    update_ip_stats(src_ip, (data_end - data) as u64)?;

    // 记录基本包信息
    info!(
        &ctx,
        "Packet: src={}, dst={}, proto={}", src_ip, dst_ip, protocol
    );

    // 处理TCP连接
    if protocol == 6 {
        handle_tcp_connection(&ctx, data, data_end, ip_offset + ip_size, src_ip, dst_ip)?;
    }

    Ok(xdp_action::XDP_PASS)
}

fn handle_tcp_connection(
    ctx: &XdpContext,
    data: usize,
    data_end: usize,
    tcp_offset: usize,
    src_ip: u32,
    dst_ip: u32,
) -> Result<(), ()> {
    let tcp_size = core::mem::size_of::<TcpHdr>();
    if data + tcp_offset + tcp_size > data_end {
        return Err(());
    }

    // 安全访问TCP头部
    let tcphdr = (data + tcp_offset) as *const TcpHdr;
    let src_port = unsafe { (*tcphdr).source };
    let dst_port = unsafe { (*tcphdr).dest };
    let flags = unsafe { (*tcphdr).flags };

    let syn = (flags & 0x02) != 0;
    let ack = (flags & 0x10) != 0;
    let fin = (flags & 0x01) != 0;
    let rst = (flags & 0x04) != 0;

    // 生成连接标识符
    let conn_key = generate_conn_key(src_ip, dst_ip, src_port, dst_port);
    let reverse_conn_key = generate_conn_key(dst_ip, src_ip, dst_port, src_port);

    // 更新连接统计
    let packet_size = (data_end - data) as u64;
    update_connection_stats(conn_key, packet_size)?;

    // 处理连接状态
    if syn && !ack {
        // SYN包 - 新连接建立
        unsafe {
            CONNECTION_TRACK.insert(&conn_key, &1, 0); // 1表示连接建立中
        }
        info!(
            ctx,
            "TCP SYN: {}:{} -> {}:{} (NEW_CONN)",
            src_ip,
            u16::from_be(src_port),
            dst_ip,
            u16::from_be(dst_port)
        );
    } else if syn && ack {
        // SYN+ACK包 - 连接确认
        unsafe {
            CONNECTION_TRACK.insert(&conn_key, &2, 0); // 2表示连接已建立
            CONNECTION_TRACK.insert(&reverse_conn_key, &2, 0);
        }
        info!(
            ctx,
            "TCP SYN+ACK: {}:{} -> {}:{} (ESTABLISHED)",
            src_ip,
            u16::from_be(src_port),
            dst_ip,
            u16::from_be(dst_port)
        );
    } else if ack && !syn {
        // ACK包 - 数据传输
        info!(
            ctx,
            "TCP ACK: {}:{} -> {}:{} (DATA)",
            src_ip,
            u16::from_be(src_port),
            dst_ip,
            u16::from_be(dst_port)
        );
    } else if fin {
        // FIN包 - 连接关闭
        unsafe {
            CONNECTION_TRACK.insert(&conn_key, &3, 0); // 3表示连接关闭中
            CONNECTION_TRACK.insert(&reverse_conn_key, &3, 0);
        }
        info!(
            ctx,
            "TCP FIN: {}:{} -> {}:{} (CLOSING)",
            src_ip,
            u16::from_be(src_port),
            dst_ip,
            u16::from_be(dst_port)
        );
    } else if rst {
        // RST包 - 连接重置
        unsafe {
            CONNECTION_TRACK.insert(&conn_key, &4, 0); // 4表示连接重置
            CONNECTION_TRACK.insert(&reverse_conn_key, &4, 0);
        }
        info!(
            ctx,
            "TCP RST: {}:{} -> {}:{} (RESET)",
            src_ip,
            u16::from_be(src_port),
            dst_ip,
            u16::from_be(dst_port)
        );
    }

    Ok(())
}

fn generate_conn_key(src_ip: u32, dst_ip: u32, src_port: u16, dst_port: u16) -> u64 {
    // 生成唯一的连接标识符
    let src_ip_u64 = src_ip as u64;
    let dst_ip_u64 = dst_ip as u64;
    let src_port_u64 = src_port as u64;
    let dst_port_u64 = dst_port as u64;
    
    // 组合IP和端口形成64位连接键
    (src_ip_u64 << 32) | dst_ip_u64 | (src_port_u64 << 48) | (dst_port_u64 << 32)
}

fn update_ip_stats(ip: u32, bytes: u64) -> Result<(), ()> {
    let mut stats = match unsafe { IP_STATS.get(&ip) } {
        Some(s) => *s,
        None => 0,
    };
    stats += bytes;
    unsafe {
        if IP_STATS.insert(&ip, &stats, 0).is_err() {
            return Err(());
        }
    }
    Ok(())
}

fn update_connection_stats(conn_key: u64, bytes: u64) -> Result<(), ()> {
    let mut stats = match unsafe { CONNECTION_STATS.get(&conn_key) } {
        Some(s) => *s,
        None => 0,
    };
    stats += bytes;
    unsafe {
        if CONNECTION_STATS.insert(&conn_key, &stats, 0).is_err() {
            return Err(());
        }
    }
    Ok(())
}

#[repr(C, packed)]
struct EthHdr {
    eth_dmac: [u8; 6],
    eth_smac: [u8; 6],
    eth_proto: u16,
}

#[repr(C, packed)]
struct IpHdr {
    version_ihl: u8,
    tos: u8,
    tot_len: u16,
    id: u16,
    frag_off: u16,
    ttl: u8,
    protocol: u8,
    check: u16,
    saddr: u32,
    daddr: u32,
}

#[repr(C, packed)]
struct TcpHdr {
    source: u16,
    dest: u16,
    seq: u32,
    ack_seq: u32,
    doff_reserved: u8,
    flags: u8,
    window: u16,
    check: u16,
    urg_ptr: u16,
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
