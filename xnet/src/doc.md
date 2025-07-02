### add traffic count to device[TC]

curl -X POST -v --noproxy '*' http://127.0.0.1:8080/traffic_count_attach_device \
  -H "Content-Type: application/json" \
  -d '{"iface": "veth0", "action": "add"}'


curl --noproxy '*' http://127.0.0.1:8080/traffic_count

```

    // XDP program
    // {
    //     let xnet_xdp: &mut Xdp = ebpf.program_mut("xnet").unwrap().try_into()?;
    //     xnet_xdp.load()?;
    //     xnet_xdp
    //         .attach(&iface, XdpFlags::default())
    //         .context("failed to attach the XDP program with SKB mode")?;
    // }

    // // TC program
    // {
    //     let xnet_tc: &mut Tc = ebpf.program_mut("xnet_tc").unwrap().try_into()?;
    //     xnet_tc.load()?;
    //     xnet_tc
    //         .attach(&iface, TcAttachType::Ingress)
    //         .context("failed to attach the TC program")?;

    //     xnet_tc
    //         .attach(&iface, TcAttachType::Egress)
    //         .context("failed to attach the TC program")?;

    // let sched_classifier = Arc::new(xnet_tc);
    // server
    // tokio::spawn(async move {

    // });
    // }

    // // 初始化流量统计
    // let mut traffic_stats = traffic::TrafficStats::new();

    // // 设置定期统计更新
    // let mut interval_timer = interval(Duration::from_secs(interval_secs));

    // let mut ctrl_c = pin!(signal::ctrl_c());

    // // 主循环

    // loop {
    //     tokio::select! {
    //         _ = interval_timer.tick() => {
    //             // 定期更新统计信息
    //             traffic_stats.last_update = Instant::now();
    //             // traffic_stats.update_from_ebpf(&ebpf);
    //             // traffic_stats.print_summary();
    //         }
    //         _ = ctrl_c.as_mut() => {
    //             println!("\n正在退出...");
    //             break;
    //         }
    //     }
    // }

```
