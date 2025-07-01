use anyhow::Context as _;
use aya::programs::{SchedClassifier as Tc, TcAttachType, Xdp, XdpFlags};
use clap::Parser;
use std::pin::pin;
use std::time::{Duration, Instant};
use tokio::time::interval;
#[rustfmt::skip]
use log::{debug, warn};
use tokio::signal;

mod server;
mod traffic;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
    #[clap(short, long, default_value = "5")]
    interval_secs: u64,
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

    // 初始化 eBPF 日志

    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        warn!("failed to initialize eBPF logger: {e}");
    }

    let Opt {
        iface,
        interval_secs,
    } = opt;

    // XDP program
    {
        let xnet_xdp: &mut Xdp = ebpf.program_mut("xnet").unwrap().try_into()?;
        xnet_xdp.load()?;
        xnet_xdp
            .attach(&iface, XdpFlags::default())
            .context("failed to attach the XDP program with SKB mode")?;
    }
    // TC program
    {
        let xnet_tc: &mut Tc = ebpf.program_mut("xnet_tc").unwrap().try_into()?;
        xnet_tc.load()?;
        xnet_tc
            .attach(&iface, TcAttachType::Ingress)
            .context("failed to attach the TC program")?;

        xnet_tc
            .attach(&iface, TcAttachType::Egress)
            .context("failed to attach the TC program")?;
    }

    if let Err(e) = server::start_server().await {
        warn!("failed to start server: {e}");
    }
    // // server
    // tokio::spawn(async move {
    //     if let Err(e) = server::start_server().await {
    //         warn!("failed to start server: {e}");
    //     }
    // });

    // 初始化流量统计
    let mut traffic_stats = traffic::TrafficStats::new();

    // 设置定期统计更新
    let mut interval_timer = interval(Duration::from_secs(interval_secs));

    let mut ctrl_c = pin!(signal::ctrl_c());

    // 主循环

    loop {
        tokio::select! {
            _ = interval_timer.tick() => {
                // 定期更新统计信息
                traffic_stats.last_update = Instant::now();
                traffic_stats.update_from_ebpf(&ebpf);
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
