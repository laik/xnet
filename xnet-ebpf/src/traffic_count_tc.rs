use aya_ebpf::{
    bindings::{TC_ACT_OK, TC_ACT_RECLASSIFY},
    macros::{classifier, map},
    maps::HashMap,
    programs::TcContext,
};
use aya_log_ebpf::{debug, info, WriteToBuf};
use xnet_common::{int_to_ip, PortStats};
use xnet_ebpf::{EthHdr, IpHdr, Protocol, TcpHdr};

// 定义端口统计map
#[map(name = "port_stats")]
static mut PORT_STATS: HashMap<u16, PortStats> = HashMap::with_max_entries(65536, 0);

// 定义总统计map
#[map(name = "total_stats")]
static mut TOTAL_STATS: HashMap<u32, u64> = HashMap::with_max_entries(2, 0);

#[classifier]
pub fn xnet_tc(ctx: TcContext) -> i32 {
    debug!(&ctx, "xnet_tc");

    let data = ctx.data();
    let data_end = ctx.data_end();
    let eth_size = core::mem::size_of::<EthHdr>();
    if data + eth_size > data_end {
        return TC_ACT_OK;
    }

    let eth_hdr = unsafe { &*(data as *const EthHdr) };
    let eth_proto = u16::from_be(eth_hdr.eth_proto);
    if eth_proto != 0x0800 {
        return TC_ACT_OK;
    }

    debug!(&ctx, "tc ingress eth_proto: {}", eth_proto);

    // 解析IP头
    let ip_offset = eth_size;
    let ip_size = core::mem::size_of::<IpHdr>();
    if data + ip_offset + ip_size > data_end {
        return TC_ACT_OK;
    }

    let ip_hdr = unsafe { &*((data + ip_offset) as *const IpHdr) };
    let protocol = ip_hdr.protocol;

    // 只处理TCP和UDP协议
    if protocol != 6 && protocol != 17 {
        return TC_ACT_OK;
    }

    // 解析TCP/UDP头获取端口信息
    let transport_offset = ip_offset + ip_size;
    let transport_size = core::mem::size_of::<TcpHdr>();
    if data + transport_offset + transport_size > data_end {
        return TC_ACT_OK;
    }

    let tcp_hdr = unsafe { &*((data + transport_offset) as *const TcpHdr) };
    let src_port = u16::from_be(tcp_hdr.source);
    let dst_port = u16::from_be(tcp_hdr.dest);

    // 获取数据包长度
    let packet_len = ctx.len() as u64;

    // 更新总统计信息
    unsafe {
        // 更新总包数
        if let Some(total_packets) = TOTAL_STATS.get(&0) {
            TOTAL_STATS.insert(&0, &(total_packets + 1), 0);
        } else {
            TOTAL_STATS.insert(&0, &1, 0);
        }

        // 更新总字节数
        if let Some(total_bytes) = TOTAL_STATS.get(&1) {
            TOTAL_STATS.insert(&1, &(total_bytes + packet_len), 0);
        } else {
            TOTAL_STATS.insert(&1, &packet_len, 0);
        }

        // 更新源端口统计
        let current_total = TOTAL_STATS.get(&0).unwrap_or(&0);
        if let Some(src_stats) = PORT_STATS.get(&src_port) {
            let new_stats = PortStats {
                packets: src_stats.packets + 1,
                bytes: src_stats.bytes + packet_len,
                last_seen: *current_total,
            };
            PORT_STATS.insert(&src_port, &new_stats, 0);
        } else {
            let new_stats = PortStats {
                packets: 1,
                bytes: packet_len,
                last_seen: *current_total,
            };
            PORT_STATS.insert(&src_port, &new_stats, 0);
        }

        // 更新目标端口统计
        if let Some(dst_stats) = PORT_STATS.get(&dst_port) {
            let new_stats = PortStats {
                packets: dst_stats.packets + 1,
                bytes: dst_stats.bytes + packet_len,
                last_seen: *current_total,
            };
            PORT_STATS.insert(&dst_port, &new_stats, 0);
        } else {
            let new_stats = PortStats {
                packets: 1,
                bytes: packet_len,
                last_seen: *current_total,
            };
            PORT_STATS.insert(&dst_port, &new_stats, 0);
        }
    }

    debug!(
        &ctx,
        "Port stats - src: {}, dst: {}, len: {}, protocol: {}",
        src_port,
        dst_port,
        packet_len,
        protocol
    );

    TC_ACT_OK
}
