use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::pin::pin;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

use anyhow::Context as _;
use aya::programs::Program;
use aya::{
    maps::Map,
    programs::{SchedClassifier as Tc, TcAttachType, Xdp, XdpFlags},
};
use clap::Parser;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use tokio::net::TcpListener;
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

// 添加 hyper 路由 post 接口，接收 json 数据，数据格式为：
// {
//     "iface": "eth0",
//     "action": "add | remove"
// }

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct MonitorRequest {
    iface: String,
    action: String,
}

async fn handle_monitor_device(
    ebpf: Arc<Mutex<aya::Ebpf>>,
    req: Request<Body>,
) -> Result<Response<Body>, hyper::Error> {
    if req.method() != Method::POST {
        return Ok(Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .body(Body::from("Method not allowed"))
            .unwrap());
    }
    if req.uri().path() != "/monitor_device" {
        return Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from("Not found"))
            .unwrap());
    }
    let whole_body = hyper::body::to_bytes(req.into_body()).await?;

    match serde_json::from_slice::<MonitorRequest>(&whole_body) {
        Ok(_request) => {
            let mut ebpf_guard = ebpf.lock().await;
            let program: &mut Tc =
                if let Ok(program) = ebpf_guard.program_mut("xnet_tc").unwrap().try_into() {
                    program
                } else {
                    return Ok(Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .body(Body::from("Failed to parse program"))
                        .unwrap());
                };

            if let Err(e) = program.load() {
                return Ok(Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::from(format!("Failed to load program: {}", e)))
                    .unwrap());
            }
            if let Err(e) = program
                .attach(&_request.iface, TcAttachType::Ingress)
                .context("failed to attach the TC program")
            {
                return Ok(Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::from(format!("Failed to attach program: {}", e)))
                    .unwrap());
            }

            Ok(Response::builder()
                .status(StatusCode::OK)
                .body(Body::from("ok"))
                .unwrap())
        }
        Err(_) => Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Body::from("Invalid JSON"))
            .unwrap()),
    }
}

async fn serve(ebpf: Arc<Mutex<aya::Ebpf>>) -> anyhow::Result<(), anyhow::Error> {
    let addr = ([0, 0, 0, 0], 8080).into();
    let make_svc = make_service_fn(move |_conn| {
        let ebpf: Arc<Mutex<aya::Ebpf>> = ebpf.clone();
        async move {
            Ok::<_, hyper::Error>(service_fn(move |req| {
                let ebpf = ebpf.clone();
                async move { handle_monitor_device(ebpf, req).await }
            }))
        }
    });
    let server = Server::bind(&addr).serve(make_svc);
    println!("HTTP 服务器启动在 http://0.0.0.0:8080");
    server.await?;
    Ok(())
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
    let ebpf = Arc::new(Mutex::new(aya::Ebpf::load(aya::include_bytes_aligned!(
        concat!(env!("OUT_DIR"), "/xnet")
    ))?));

    // 初始化 eBPF 日志
    {
        let mut ebpf_guard = ebpf.lock().await;
        if let Err(e) = aya_log::EbpfLogger::init(&mut *ebpf_guard) {
            warn!("failed to initialize eBPF logger: {e}");
        }
    }

    let Opt {
        iface,
        interval_secs,
    } = opt;

    // XDP program
    {
        let mut ebpf_guard = ebpf.lock().await;
        let program: &mut Xdp = ebpf_guard.program_mut("xnet").unwrap().try_into()?;
        program.load()?;
        program
            .attach(&iface, XdpFlags::default())
            .context("failed to attach the XDP program with SKB mode")?;
    }
    // TC program
    {
        let mut ebpf_guard = ebpf.lock().await;
        let program: &mut Tc = ebpf_guard.program_mut("xnet_tc").unwrap().try_into()?;
        program.load()?;
        program
            .attach(&iface, TcAttachType::Ingress)
            .context("failed to attach the TC program")?;
    }

    // 初始化流量统计
    let mut traffic_stats = TrafficStats::new();

    // 设置定期统计更新
    let mut interval_timer = interval(Duration::from_secs(interval_secs));

    println!("XNet 流量监控已启动");
    println!("监控接口: {}", iface);
    println!("统计间隔: {} 秒", interval_secs);
    println!("按 Ctrl-C 退出...\n");

    let mut ctrl_c = pin!(signal::ctrl_c());

    // 启动 HTTP 服务
    let ebpf_clone = ebpf.clone();
    tokio::spawn(async move {
        if let Err(e) = serve(ebpf_clone).await {
            eprintln!("HTTP 服务器错误: {}", e);
        }
    });

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
