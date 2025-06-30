use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::pin::pin;
use std::ptr;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use aya::{
    maps::Map,
    programs::{Xdp, XdpFlags},
};
use clap::Parser;
#[rustfmt::skip]
use log::{debug, warn, info};
use tokio::signal;
use tokio::time::interval;
use xnet_common::LogEvent;



#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
    #[clap(short, long, default_value = "5")]
    interval_secs: u64,
}

struct ConnectionInfo {
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    status: u32,
    bytes: u64,
    last_seen: Instant,
}

struct TrafficStats {
    ip_stats: HashMap<u32, u64>,
    connections: HashMap<u64, ConnectionInfo>,
    last_update: Instant,
}

impl TrafficStats {
    fn new() -> Self {
        Self {
            ip_stats: HashMap::new(),
            connections: HashMap::new(),
            last_update: Instant::now(),
        }
    }

    fn print_summary(&self) {
        println!("\n=== 流量统计汇总 ===");
        println!("更新时间: {:?}", self.last_update.elapsed());

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
        println!("========================\n");
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // 加载eBPF程序
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/xnet"
    )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        warn!("failed to initialize eBPF logger: {e}");
    }

    let Opt {
        iface,
        interval_secs,
    } = opt;
    let program: &mut Xdp = ebpf.program_mut("xnet").unwrap().try_into()?;
    program.load()?;
    program
        .attach(&iface, XdpFlags::default())
        .context("failed to attach the XDP program with SKB mode")?;

    // 初始化流量统计
    let mut traffic_stats = TrafficStats::new();

    // 设置定期统计更新
    let mut interval_timer = interval(Duration::from_secs(interval_secs));

    println!("XNet 流量监控已启动");
    println!("监控接口: {}", iface);
    println!("统计间隔: {} 秒", interval_secs);
    println!("按 Ctrl-C 退出...\n");

    let mut ctrl_c = pin!(signal::ctrl_c());

    loop {
        tokio::select! {
            _ = interval_timer.tick() => {
                // 定期更新统计信息
                traffic_stats.last_update = Instant::now();
                traffic_stats.print_summary();
            }
            _ = ctrl_c.as_mut() => {
                println!("\n正在退出...");
                break;
            }
        }
    }

    Ok(())
}
