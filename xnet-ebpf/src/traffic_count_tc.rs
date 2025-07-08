use aya_ebpf::{
    bindings::{TC_ACT_OK, TC_ACT_RECLASSIFY},
    macros::{classifier, map},
    maps::HashMap,
    programs::TcContext,
};
use aya_log_ebpf::{debug, info, WriteToBuf};
use xnet_common::{int_to_ip, DeviceConnectionStats, DeviceStats, PortStats};
use xnet_ebpf::{EthHdr, IpHdr, Protocol, TcpHdr};

// 定义端口统计map
#[map(name = "port_stats")]
static mut PORT_STATS: HashMap<u16, PortStats> = HashMap::with_max_entries(65536, 0);

// 定义总统计map
#[map(name = "total_stats")]
static mut TOTAL_STATS: HashMap<u32, u64> = HashMap::with_max_entries(2, 0);

// 定义设备map流量统计，key为设备名_方向，value为流量统计
// 流量统计包含总包数、总字节数、最后活跃时间
#[map(name = "device_stats")]
static mut DEVICE_STATS: HashMap<u32, DeviceStats> = HashMap::with_max_entries(1024, 0);

// 设备名称到ID的映射，用于生成key
#[map(name = "device_map")]
static mut DEVICE_MAP: HashMap<[u8; 16], u32> = HashMap::with_max_entries(64, 0);

// 当前设备上下文信息 - 使用设备ID作为key，如果没有此上下文，则不会统计流量
#[map(name = "device_context")]
static mut DEVICE_CONTEXT: HashMap<u32, u32> = HashMap::with_max_entries(64, 0);

// 记录设备的连接的信息，例如 device_id, src_port, dst_port, direction, protocol, timestamp, total_packets, total_bytes
#[map(name = "device_connection_stats")]
static mut DEVICE_CONNECTION_STATS: HashMap<u32, DeviceConnectionStats> =
    HashMap::with_max_entries(1024, 0);

// 生成设备统计key的函数
fn generate_device_key(device_id: u32, is_ingress: bool) -> u32 {
    // 使用设备ID和方向生成key
    // 偶数表示ingress，奇数表示egress
    if is_ingress {
        device_id * 2
    } else {
        device_id * 2 + 1
    }
}

// 生成设备连接统计key的函数
fn generate_connection_key(
    device_id: u32,
    src_port: u16,
    dst_port: u16,
    direction: u32,
    protocol: u32,
) -> u32 {
    // 使用设备ID、端口、方向和协议生成key
    // 使用简单的哈希算法组合这些值
    let mut key = device_id;
    key = key.wrapping_add(src_port as u32);
    key = key.wrapping_add((dst_port as u32) << 16);
    key = key.wrapping_add(direction << 24);
    key = key.wrapping_add(protocol << 28);
    key
}

// 检查设备是否为veth设备
fn is_veth_device(device_id: u32) -> bool {
    unsafe {
        // 遍历DEVICE_MAP，查找device_id对应的设备名
        let mut name_buf: [u8; 16] = [0; 16];
        let mut found = false;
        for i in 0u8..64u8 {
            name_buf[0] = i;
            // 这里只能遍历所有可能的key（实际部署时建议优化）
            if let Some(&id) = DEVICE_MAP.get(&name_buf) {
                if id == device_id {
                    // 判断前缀是否为"veth"
                    if name_buf[0] == b'v'
                        && name_buf[1] == b'e'
                        && name_buf[2] == b't'
                        && name_buf[3] == b'h'
                    {
                        found = true;
                        break;
                    }
                }
            }
        }
        found
    }
}

// 从设备映射中获取设备名称（如果可用）
fn get_device_name_from_id(device_id: u32) -> Option<[u8; 16]> {
    unsafe {
        for i in 0u8..64u8 {
            let mut name_buf = [0u8; 16];
            name_buf[0] = i;
            if let Some(&id) = DEVICE_MAP.get(&name_buf) {
                if id == device_id {
                    return Some(name_buf);
                }
            }
        }
        None
    }
}

// 根据设备类型调整方向
fn adjust_direction_for_device(device_id: u32, is_ingress: bool) -> u32 {
    if is_veth_device(device_id) {
        // 如果是veth设备，方向相反
        if is_ingress {
            1
        } else {
            0
        }
    } else {
        // 其他设备保持原方向
        if is_ingress {
            0
        } else {
            1
        }
    }
}

// 查询设备连接统计的辅助函数
fn query_device_connection_stats(device_id: u32) -> Option<DeviceConnectionStats> {
    unsafe {
        // 遍历所有可能的连接统计，查找匹配的设备ID
        for key in 0..1024 {
            if let Some(stats) = DEVICE_CONNECTION_STATS.get(&key) {
                if stats.device_id == device_id {
                    return Some(*stats);
                }
            }
        }
        None
    }
}

// 更新设备统计信息
fn update_device_stats(device_id: u32, is_ingress: bool, packet_len: u64) -> Result<(), ()> {
    let key = generate_device_key(device_id, is_ingress);

    unsafe {
        let current_total = TOTAL_STATS.get(&0).unwrap_or(&0);

        if let Some(stats) = DEVICE_STATS.get(&key) {
            let new_stats = DeviceStats {
                packets: stats.packets + 1,
                bytes: stats.bytes + packet_len,
                last_seen: *current_total,
            };
            DEVICE_STATS.insert(&key, &new_stats, 0);
        } else {
            let new_stats = DeviceStats {
                packets: 1,
                bytes: packet_len,
                last_seen: *current_total,
            };
            DEVICE_STATS.insert(&key, &new_stats, 0);
        }
    }

    Ok(())
}

// 更新设备连接统计信息
fn update_device_connection_stats(
    device_id: u32,
    src_port: u16,
    dst_port: u16,
    is_ingress: bool,
    protocol: u8,
    packet_len: u64,
) -> Result<(), ()> {
    let direction = adjust_direction_for_device(device_id, is_ingress);
    let protocol_u32 = protocol as u32;
    let key = generate_connection_key(device_id, src_port, dst_port, direction, protocol_u32);

    unsafe {
        let current_total = TOTAL_STATS.get(&0).unwrap_or(&0);

        if let Some(stats) = DEVICE_CONNECTION_STATS.get(&key) {
            let new_stats = DeviceConnectionStats {
                device_id: stats.device_id,
                src_port: stats.src_port,
                dst_port: stats.dst_port,
                direction: stats.direction,
                protocol: stats.protocol,
                timestamp: *current_total,
                total_packets: stats.total_packets + 1,
                total_bytes: stats.total_bytes + packet_len,
            };
            DEVICE_CONNECTION_STATS.insert(&key, &new_stats, 0);
        } else {
            let new_stats = DeviceConnectionStats {
                device_id,
                src_port,
                dst_port,
                direction,
                protocol: protocol_u32,
                timestamp: *current_total,
                total_packets: 1,
                total_bytes: packet_len,
            };
            DEVICE_CONNECTION_STATS.insert(&key, &new_stats, 0);
        }
    }

    Ok(())
}

// 获取当前设备上下文
fn get_current_device_context() -> Option<(u32, bool)> {
    unsafe {
        // 从设备上下文中获取当前设备ID和方向
        // 遍历所有设备上下文，找到匹配的设备ID
        for device_id in 1..64 {
            if let Some(context) = DEVICE_CONTEXT.get(&device_id) {
                let is_ingress = (*context >> 16) & 1 == 0;
                return Some((device_id, is_ingress));
            }
        }
        // 如果没有找到上下文，返回None表示不统计
        None
    }
}

// 根据TC挂载点确定方向
fn get_tc_direction(ctx: &TcContext) -> bool {
    // 这里我们需要根据TC程序的挂载点来确定方向
    // 由于eBPF无法直接获取挂载点信息，我们使用一个简化的方案
    // 在实际部署中，ingress和egress会使用不同的程序实例
    true // 暂时返回true，表示ingress
         // let mark = ctx.skb.mark();
         // let is_ingress = mark & 1 == 0;
         // return is_ingress;
}

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
    }

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

    // 更新端口统计信息
    unsafe {
        let current_total = TOTAL_STATS.get(&0).unwrap_or(&0);

        // 更新源端口统计
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

    // 获取当前设备上下文
    if let Some((device_id, is_ingress)) = get_current_device_context() {
        // 更新设备统计
        let _ = update_device_stats(device_id, is_ingress, packet_len);

        // 更新设备连接统计
        let _ = update_device_connection_stats(
            device_id, src_port, dst_port, is_ingress, protocol, packet_len,
        );
    }

    // 记录调试信息
    if let Some((device_id, is_ingress)) = get_current_device_context() {
        debug!(
            &ctx,
            "Port stats - src: {}, dst: {}, len: {}, protocol: {}, device: {}, direction: {}",
            src_port,
            dst_port,
            packet_len,
            protocol,
            device_id,
            if is_ingress { "ingress" } else { "egress" }
        );
    } else {
        debug!(
            &ctx,
            "Port stats - src: {}, dst: {}, len: {}, protocol: {} (no device context)",
            src_port,
            dst_port,
            packet_len,
            protocol
        );
    }

    TC_ACT_OK
}
