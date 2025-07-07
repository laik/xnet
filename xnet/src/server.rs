use std::collections::HashMap;
use std::sync::Arc;

use axum::response::IntoResponse;
use axum::Extension;
use axum::{extract::Json, http::StatusCode, Router};
use aya::programs::tc::SchedClassifierLinkId;
use aya::programs::Xdp;
use aya::programs::{SchedClassifier as Tc, TcAttachType};
use aya::Ebpf;
use log::info;
use tokio::sync::Mutex;

use crate::traffic::TrafficStats;

// 包装 eBPF 实例，提供线程安全的可变访问
pub struct EbpfManager {
    ebpf: Mutex<Ebpf>,
}

impl EbpfManager {
    pub fn new(ebpf: Ebpf) -> Self {
        Self {
            ebpf: Mutex::new(ebpf),
        }
    }

    // 加载所有 eBPF 程序
    pub async fn load_programs(&self) -> Result<(), anyhow::Error> {
        let mut ebpf = self.ebpf.lock().await;

        // 加载 XDP 程序
        let xnet_xdp = ebpf.program_mut("xnet_xdp").unwrap();
        let xnet_xdp: &mut Xdp = xnet_xdp.try_into().unwrap();
        xnet_xdp.load()?;
        info!("xnet_xdp program loaded");

        // 加载 TC 程序
        let xnet_tc = ebpf.program_mut("xnet_tc").unwrap();
        let xnet_tc: &mut Tc = xnet_tc.try_into().unwrap();
        xnet_tc.load()?;
        info!("xnet_tc program loaded");

        Ok(())
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
enum Action {
    Add = 1,
    Remove = 2,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct TrafficCountDeviceRequest {
    iface: String,
    action: Action,
}

lazy_static::lazy_static! {
    static ref TC_LINK_ID: Mutex<HashMap<String, SchedClassifierLinkId>> = Mutex::new(HashMap::new());
}

fn key_from_iface(iface: &str, attach_type: TcAttachType) -> String {
    format!("xnet_tc_{}_{:?}", iface, attach_type)
}

// 查询对应接口的流量统计信息
async fn traffic_count(Extension(ebpf_manager): Extension<Arc<EbpfManager>>) -> impl IntoResponse {
    let mut traffic_stats = crate::traffic::TRAFFIC_STATS.lock().await;
    let ebpf = ebpf_manager.ebpf.lock().await;
    traffic_stats.update_from_ebpf(&ebpf);
    // traffic_stats.print_summary();
    traffic_stats.return_summary()
}

async fn traffic_count_attach_device(
    Extension(ebpf_manager): Extension<Arc<EbpfManager>>,
    Json(request): Json<TrafficCountDeviceRequest>,
) -> impl IntoResponse {
    info!(
        "traffic_count_attach_device 处理请求: iface={}, action={:?}",
        request.iface, request.action
    );

    match request.action {
        Action::Add => {
            // 检查接口是否存在
            if !std::path::Path::new(&format!("/sys/class/net/{}", request.iface)).exists() {
                info!("错误: 接口 {} 不存在", request.iface);
                return (
                    StatusCode::BAD_REQUEST,
                    format!("Interface {} does not exist", request.iface),
                );
            }

            // 检查是否已经有TC程序附加到该接口
            let tc_check_path = format!("/sys/fs/bpf/tc/globals/xnet_tc_{}", request.iface);
            if std::path::Path::new(&tc_check_path).exists() {
                info!("警告: TC程序已经附加到接口 {}，跳过附加操作", request.iface);
                return (StatusCode::OK, "TC program already attached".to_string());
            }

            // 获取 eBPF 实例的可变访问
            let mut ebpf = ebpf_manager.ebpf.lock().await;
            let tc: &mut Tc = ebpf.program_mut("xnet_tc").unwrap().try_into().unwrap();

            let link_id = tc.attach(&request.iface, TcAttachType::Ingress).unwrap();
            TC_LINK_ID.lock().await.insert(
                key_from_iface(&request.iface, TcAttachType::Ingress),
                link_id,
            );

            let link_id = tc.attach(&request.iface, TcAttachType::Egress).unwrap();
            TC_LINK_ID.lock().await.insert(
                key_from_iface(&request.iface, TcAttachType::Egress),
                link_id,
            );

            (StatusCode::OK, "ok".to_string())
        }
        Action::Remove => {
            let mut ebpf = ebpf_manager.ebpf.lock().await;
            let tc: &mut Tc = ebpf.program_mut("xnet_tc").unwrap().try_into().unwrap();

            let ingress_link_id = TC_LINK_ID
                .lock()
                .await
                .remove(&key_from_iface(&request.iface, TcAttachType::Ingress));
            let egress_link_id = TC_LINK_ID
                .lock()
                .await
                .remove(&key_from_iface(&request.iface, TcAttachType::Egress));

            if let Some(link_id) = ingress_link_id {
                tc.detach(link_id).unwrap();
            }
            if let Some(link_id) = egress_link_id {
                tc.detach(link_id).unwrap();
            }
            (StatusCode::OK, "ok".to_string())
        }
    }
}

pub async fn serve(ebpf: aya::Ebpf) -> Result<(), anyhow::Error> {
    // 创建 eBPF 管理器
    let ebpf_manager = Arc::new(EbpfManager::new(ebpf));

    // 加载 eBPF 程序
    ebpf_manager.load_programs().await?;

    #[rustfmt::skip]
    let router = Router::new()
        .route("/", axum::routing::get(|| async {"ok"}))
        .route("/traffic_count", axum::routing::get(traffic_count))
        .route("/traffic_count_attach_device", axum::routing::post(traffic_count_attach_device))
        .layer(Extension(ebpf_manager))
    ;

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;

    info!("HTTP 服务器启动在 http://0.0.0.0:8080");

    axum::serve(listener, router).await?;

    Ok(())
}
