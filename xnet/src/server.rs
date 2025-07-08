use std::collections::HashMap;
use std::sync::Arc;

use axum::response::IntoResponse;
use axum::Extension;
use axum::{extract::{Json, Path}, http::StatusCode, Router};
use aya::maps::HashMap as AyaHashMap;
use aya::maps::MapData;
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

    // 设置设备映射
    pub async fn set_device_mapping(
        &self,
        device_name: &str,
        device_id: u32,
    ) -> Result<(), anyhow::Error> {
        let mut ebpf = self.ebpf.lock().await;

        if let Some(device_map) = ebpf.map_mut("device_map") {
            if let Ok(mut device_map) =
                AyaHashMap::<&mut MapData, [u8; 16], u32>::try_from(device_map)
            {
                // 将设备名称转换为字节数组
                let mut device_bytes = [0u8; 16];
                let name_bytes = device_name.as_bytes();
                let copy_len = std::cmp::min(name_bytes.len(), 16);
                device_bytes[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

                device_map.insert(&device_bytes, &device_id, 0)?;
                info!("设备映射设置成功: {} -> {}", device_name, device_id);
            }
        }

        Ok(())
    }

    // 设置设备上下文
    pub async fn set_device_context(
        &self,
        device_id: u32,
        is_ingress: bool,
    ) -> Result<(), anyhow::Error> {
        let mut ebpf = self.ebpf.lock().await;

        if let Some(device_context) = ebpf.map_mut("device_context") {
            if let Ok(mut device_context) =
                AyaHashMap::<&mut MapData, u32, u32>::try_from(device_context)
            {
                // 将设备ID和方向编码到一个u32中
                let context_value = device_id | ((if is_ingress { 0 } else { 1 }) << 16);
                device_context.insert(&device_id, &context_value, 0)?;
                info!(
                    "设备上下文设置成功: device_id={}, direction={}",
                    device_id,
                    if is_ingress { "ingress" } else { "egress" }
                );
            }
        }

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
    pub static ref DEVICE_MAPPINGS: Mutex<HashMap<String, u32>> = Mutex::new(HashMap::new());
}

fn key_from_iface(iface: &str, attach_type: TcAttachType) -> String {
    format!("xnet_tc_{}_{:?}", iface, attach_type)
}

// 查询设备映射及流量统计
async fn traffic_device_state(
    Extension(ebpf_manager): Extension<Arc<EbpfManager>>,
) -> impl IntoResponse {
    let mut traffic_stats = crate::traffic::TRAFFIC_STATS.lock().await;
    let ebpf = ebpf_manager.ebpf.lock().await;
    traffic_stats.update_from_ebpf(&ebpf);
    let device_stats = traffic_stats.return_device_stats();
    (StatusCode::OK, Json(device_stats))
}

// 查询设备连接统计
async fn traffic_device_connection_stats(
    Extension(ebpf_manager): Extension<Arc<EbpfManager>>,
) -> impl IntoResponse {
    let mut traffic_stats = crate::traffic::TRAFFIC_STATS.lock().await;
    let ebpf = ebpf_manager.ebpf.lock().await;
    traffic_stats.update_from_ebpf(&ebpf);
    let connection_stats = traffic_stats.return_device_connection_stats();
    (StatusCode::OK, Json(connection_stats))
}

// 查询指定设备的连接统计
async fn traffic_device_connection_stats_by_id(
    Extension(ebpf_manager): Extension<Arc<EbpfManager>>,
    Path(device_id): Path<u32>,
) -> impl IntoResponse {
    let mut traffic_stats = crate::traffic::TRAFFIC_STATS.lock().await;
    let ebpf = ebpf_manager.ebpf.lock().await;
    traffic_stats.update_from_ebpf(&ebpf);
    let connection_stats = traffic_stats.query_device_connection_stats(device_id);
    
    let mut result = Vec::new();
    for stats in connection_stats {
        let direction_str = if stats.direction == 0 { "ingress" } else { "egress" };
        let protocol_str = if stats.protocol == 6 { "TCP" } else if stats.protocol == 17 { "UDP" } else { "UNKNOWN" };
        
        let stats_info = serde_json::json!({
            "device_id": stats.device_id,
            "src_port": stats.src_port,
            "dst_port": stats.dst_port,
            "direction": direction_str,
            "protocol": protocol_str,
            "timestamp": stats.timestamp,
            "total_packets": stats.total_packets,
            "total_bytes": stats.total_bytes
        });
        
        result.push(stats_info);
    }
    
    (StatusCode::OK, Json(result))
}

// 查询对应接口的流量统计信息
async fn traffic_count(Extension(ebpf_manager): Extension<Arc<EbpfManager>>) -> impl IntoResponse {
    let mut traffic_stats = crate::traffic::TRAFFIC_STATS.lock().await;
    let ebpf = ebpf_manager.ebpf.lock().await;
    traffic_stats.update_from_ebpf(&ebpf);
    traffic_stats.print_summary();
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
            // 查询linux系统中是否存在该设备
            if !std::path::Path::new(&format!("/sys/class/net/{}", request.iface)).exists() {
                return (
                    StatusCode::BAD_REQUEST,
                    format!("Interface {} does not exist", request.iface),
                );
            }
            // 获取对应的device_id, cat /sys/class/net/eth0/ifindex
            let device_id =
                std::fs::read_to_string(&format!("/sys/class/net/{}/ifindex", request.iface))
                    .unwrap()
                    .trim()
                    .parse::<u32>()
                    .unwrap();

            // 保存设备映射到内存
            DEVICE_MAPPINGS
                .lock()
                .await
                .insert(request.iface.clone(), device_id);

            // 设置设备映射到eBPF
            if let Err(e) = ebpf_manager
                .set_device_mapping(&request.iface, device_id)
                .await
            {
                info!("设置设备映射失败: {}", e);
            }

            // 获取 eBPF 实例的可变访问
            let mut ebpf = ebpf_manager.ebpf.lock().await;
            let tc: &mut Tc = ebpf.program_mut("xnet_tc").unwrap().try_into().unwrap();

            // 挂载到 ingress
            let link_id = tc.attach(&request.iface, TcAttachType::Ingress).unwrap();
            TC_LINK_ID.lock().await.insert(
                key_from_iface(&request.iface, TcAttachType::Ingress),
                link_id,
            );

            // 挂载到 egress
            let link_id = tc.attach(&request.iface, TcAttachType::Egress).unwrap();
            TC_LINK_ID.lock().await.insert(
                key_from_iface(&request.iface, TcAttachType::Egress),
                link_id,
            );

            // 释放ebpf锁后再设置设备上下文
            drop(ebpf);

            // 设置 ingress 设备上下文
            if let Err(e) = ebpf_manager.set_device_context(device_id, true).await {
                info!("设置 ingress 设备上下文失败: {}", e);
            }

            // 等待一下，确保ingress上下文设置完成
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

            // 设置 egress 设备上下文
            if let Err(e) = ebpf_manager.set_device_context(device_id, false).await {
                info!("设置 egress 设备上下文失败: {}", e);
            }

            info!("设备 {} 已挂载，设备ID: {}", request.iface, device_id);
            (
                StatusCode::OK,
                format!("设备 {} 挂载成功，设备ID: {}", request.iface, device_id),
            )
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

            // 从内存映射中移除设备
            DEVICE_MAPPINGS.lock().await.remove(&request.iface);

            info!("设备 {} 已移除", request.iface);
            (StatusCode::OK, format!("设备 {} 移除成功", request.iface))
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
        .route("/traffic_device_state", axum::routing::get(traffic_device_state))
        .route("/traffic_device_connection_stats", axum::routing::get(traffic_device_connection_stats))
        .route("/traffic_device_connection_stats/:device_id", axum::routing::get(traffic_device_connection_stats_by_id))
        .layer(Extension(ebpf_manager))
    ;

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;

    info!("HTTP 服务器启动在 http://0.0.0.0:8080");

    axum::serve(listener, router).await?;

    Ok(())
}
