use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};

use aya_log_ebpf::{debug, info};
use xnet_common::int_to_ip;
use xnet_ebpf::{EthHdr, IpHdr, Protocol, TcpHdr, UdpHdr};

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
    debug!(
        &ctx,
        "IP Packet: src={}, dst={}, proto={}",
        int_to_ip(src_ip),
        int_to_ip(dst_ip),
        Protocol(protocol)
    );

    // 处理TCP连接
    if protocol == 6 {
        handle_tcp_connection(&ctx, data, data_end, ip_offset + ip_size, src_ip, dst_ip)?;
    } else if protocol == 17 {
        handle_udp_connection(&ctx, data, data_end, ip_offset + ip_size, src_ip, dst_ip)?;
    }

    Ok(xdp_action::XDP_PASS)
}

fn handle_udp_connection(
    ctx: &XdpContext,
    data: usize,
    data_end: usize,
    udp_offset: usize,
    src_ip: u32,
    dst_ip: u32,
) -> Result<(), ()> {
    let udp_size = core::mem::size_of::<UdpHdr>();
    if data + udp_offset + udp_size > data_end {
        return Err(());
    }

    // 安全访问UDP头部
    let udphdr = (data + udp_offset) as *const UdpHdr;
    let src_port = unsafe { (*udphdr).source };
    let dst_port = unsafe { (*udphdr).dest };
    let _udp_len = unsafe { (*udphdr).len };

    // 更新IP统计
    update_ip_stats(src_ip, (data_end - data) as u64)?;
    update_ip_stats(dst_ip, (data_end - data) as u64)?;

    // 记录UDP数据包
    info!(
        ctx,
        "UDP: {}:{} -> {}:{}",
        int_to_ip(src_ip),
        u16::from_be(src_port),
        int_to_ip(dst_ip),
        u16::from_be(dst_port)
    );

    Ok(())
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
            let _ = CONNECTION_TRACK.insert(&conn_key, &1, 0); // 1表示连接建立中
        }
        debug!(
            ctx,
            "TCP SYN: {}:{} -> {}:{} (NEW_CONN)",
            int_to_ip(src_ip),
            u16::from_be(src_port),
            int_to_ip(dst_ip),
            u16::from_be(dst_port)
        );
    } else if syn && ack {
        // SYN+ACK包 - 连接确认
        unsafe {
            let _ = CONNECTION_TRACK.insert(&conn_key, &2, 0); // 2表示连接已建立
            let _ = CONNECTION_TRACK.insert(&reverse_conn_key, &2, 0);
        }
        debug!(
            ctx,
            "TCP SYN+ACK: {}:{} -> {}:{} (ESTABLISHED)",
            int_to_ip(src_ip),
            u16::from_be(src_port),
            int_to_ip(dst_ip),
            u16::from_be(dst_port)
        );
    } else if ack && !syn {
        // ACK包 - 数据传输
        debug!(
            ctx,
            "TCP ACK: {}:{} -> {}:{} (DATA)",
            int_to_ip(src_ip),
            u16::from_be(src_port),
            int_to_ip(dst_ip),
            u16::from_be(dst_port)
        );
    } else if fin {
        // FIN包 - 连接关闭
        unsafe {
            let _ = CONNECTION_TRACK.insert(&conn_key, &3, 0); // 3表示连接关闭中
            let _ = CONNECTION_TRACK.insert(&reverse_conn_key, &3, 0);
        }
        info!(
            ctx,
            "TCP FIN: {}:{} -> {}:{} (CLOSING)",
            int_to_ip(src_ip),
            u16::from_be(src_port),
            int_to_ip(dst_ip),
            u16::from_be(dst_port)
        );
    } else if rst {
        // RST包 - 连接重置
        unsafe {
            let _ = CONNECTION_TRACK.insert(&conn_key, &4, 0); // 4表示连接重置
            let _ = CONNECTION_TRACK.insert(&reverse_conn_key, &4, 0);
        }
        info!(
            ctx,
            "TCP RST: {}:{} -> {}:{} (RESET)",
            int_to_ip(src_ip),
            u16::from_be(src_port),
            int_to_ip(dst_ip),
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
