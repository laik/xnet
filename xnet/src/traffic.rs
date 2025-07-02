use aya::maps::HashMap as AyaHashMap;
use aya::maps::MapData;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::Instant;
use xnet_common::PortStats;

use serde_json::Map as JsonMap;
use serde_json::Value;

pub struct ConnectionInfo {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub status: u32,
    pub bytes: u64,
    pub last_seen: Instant,
}

pub struct TrafficStats {
    pub ip_stats: HashMap<u32, u64>,
    pub connections: HashMap<u64, ConnectionInfo>,
    pub last_update: Instant,
    pub port_stats: HashMap<u16, PortStats>,
    pub total_packets: u64,
    pub total_bytes: u64,
}

impl TrafficStats {
    pub fn new() -> Self {
        Self {
            ip_stats: HashMap::new(),
            connections: HashMap::new(),
            last_update: Instant::now(),
            port_stats: HashMap::new(),
            total_packets: 0,
            total_bytes: 0,
        }
    }

    pub fn update_from_ebpf(&mut self, ebpf: &aya::Ebpf) {
        // 读取总统计信息
        if let Some(total_stats) = ebpf.map("total_stats") {
            if let Ok(total_stats_map) = AyaHashMap::<&MapData, u32, u64>::try_from(&*total_stats) {
                if let Ok(total_packets) = total_stats_map.get(&0, 0) {
                    self.total_packets = total_packets;
                }
                if let Ok(total_bytes) = total_stats_map.get(&1, 0) {
                    self.total_bytes = total_bytes;
                }
            }
        }

        // 读取端口统计信息
        if let Some(port_stats) = ebpf.map("port_stats") {
            if let Ok(port_stats_map) =
                AyaHashMap::<&MapData, u16, PortStats>::try_from(&*port_stats)
            {
                // 遍历所有端口统计
                for port in 0..u16::MAX {
                    match port_stats_map.get(&port, 0) {
                        Ok(stats) if stats.packets > 0 => {
                            self.port_stats.insert(port, stats);
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    // 从ebpf中获取每个IP的流量统计，返回一个JSON对象
    pub fn report_ip_stats(&self) -> JsonMap<String, Value> {
        let mut map = JsonMap::<String, Value>::new();
        for (ip, bytes) in self.ip_stats.iter() {
            map.insert(
                ip.to_string(),
                Value::Number(bytes.to_string().parse().unwrap()),
            );
        }
        map
    }

    pub fn print_summary(&self) {
        println!("\n=== 流量统计汇总 ===");
        println!("更新时间: {:?}", self.last_update.elapsed());
        println!("总包数: {}", self.total_packets);
        println!(
            "总字节数: {:.2} MB",
            self.total_bytes as f64 / (1024.0 * 1024.0)
        );

        // 显示端口流量统计
        println!("\n--- 端口流量统计 (Top 20) ---");
        let mut sorted_ports: Vec<_> = self.port_stats.iter().collect();
        sorted_ports.sort_by(|a, b| b.1.bytes.cmp(&a.1.bytes));

        for (port, stats) in sorted_ports.iter().take(20) {
            let mb = stats.bytes as f64 / (1024.0 * 1024.0);
            let kb = stats.bytes as f64 / 1024.0;
            let traffic_str = if mb >= 1.0 {
                format!("{:.2} MB", mb)
            } else {
                format!("{:.2} KB", kb)
            };
            println!(
                "端口: {:5} | 包数: {:8} | 流量: {:>10} | 最后活跃: {:8}",
                port, stats.packets, traffic_str, stats.last_seen
            );
        }

        // 显示IP流量统计
        println!("\n--- IP流量统计 ---");
        let mut sorted_ips: Vec<_> = self.ip_stats.iter().collect();
        sorted_ips.sort_by(|a, b| b.1.cmp(a.1));

        for (ip, bytes) in sorted_ips.iter().take(10) {
            let ip_addr = Ipv4Addr::from(**ip);
            let mb = **bytes as f64 / (1024.0 * 1024.0);
            println!("IP: {:15} | 流量: {:.2} MB", ip_addr, mb);
        }

        // 显示连接统计
        println!("\n--- 活跃连接 ---");
        let mut active_connections: Vec<_> = self
            .connections
            .iter()
            .filter(|(_, conn)| conn.status == 2) // 只显示已建立的连接
            .collect();
        active_connections.sort_by(|a, b| b.1.bytes.cmp(&a.1.bytes));

        for (_, conn) in active_connections.iter().take(10) {
            let src_ip = Ipv4Addr::from(conn.src_ip);
            let dst_ip = Ipv4Addr::from(conn.dst_ip);
            let mb = conn.bytes as f64 / (1024.0 * 1024.0);
            let status_str = match conn.status {
                1 => "建立中",
                2 => "已建立",
                3 => "关闭中",
                4 => "已重置",
                _ => "未知",
            };
            println!(
                "{}:{} -> {}:{} | 状态: {} | 流量: {:.2} MB",
                src_ip, conn.src_port, dst_ip, conn.dst_port, status_str, mb
            );
        }

        println!("总连接数: {}", self.connections.len());
        println!("活跃连接数: {}", active_connections.len());
        println!("活跃端口数: {}", self.port_stats.len());
        println!("========================\n");
    }
}
