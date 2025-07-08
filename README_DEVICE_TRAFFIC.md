# 设备流量统计功能

## 概述

本功能为每个网络设备提供上行（ingress）和下行（egress）流量统计，支持多个设备同时监控，每个设备都有独立的流量统计。

## 功能特性

### 1. 设备流量统计
- **多设备支持**: 同时监控多个网络设备
- **双向流量**: 分别统计每个设备的 ingress（上行）和 egress（下行）流量
- **实时统计**: 实时更新包数、字节数和最后活跃时间
- **设备映射**: 支持设备名称到ID的映射

### 2. 统计维度
- **包数统计**: 每个设备每个方向的包数量
- **字节统计**: 每个设备每个方向的字节数
- **时间统计**: 最后活跃时间戳
- **方向区分**: ingress（入站）和 egress（出站）

### 3. 数据结构
```rust
pub struct DeviceStats {
    pub packets: u64,    // 包数
    pub bytes: u64,      // 字节数
    pub last_seen: u64,  // 最后活跃时间
}
```

## 使用方法

### 1. 挂载设备到TC

将设备挂载到TC程序进行流量监控。系统会自动为设备分配ID并设置映射：

```bash
curl -X POST -v --noproxy '*' http://127.0.0.1:8080/traffic_count_attach_device \
  -H "Content-Type: application/json" \
  -d '{"iface": "veth0", "action": "add"}'
```

### 2. 查询流量统计

查询所有设备的流量统计信息：

```bash
curl --noproxy '*' http://127.0.0.1:8080/traffic_count
```

### 3. 移除设备监控

移除设备的流量监控：

```bash
curl -X POST -v --noproxy '*' http://127.0.0.1:8080/traffic_count_attach_device \
  -H "Content-Type: application/json" \
  -d '{"iface": "veth0", "action": "remove"}'
```

## 输出示例

### 流量统计输出
```
=== 流量统计汇总 ===
更新时间: 5.2s
总包数: 12345
总字节数: 15.67 MB
活跃连接数: 156
活跃端口数: 45
活跃设备数: 4
========================

--- 设备流量统计 ---
设备: veth0_ingress    | 包数:     1234 | 流量:    2.34 MB | 最后活跃:    12345
设备: veth0_egress     | 包数:     1234 | 流量:    2.34 MB | 最后活跃:    12344
设备: veth1_ingress    | 包数:      567 | 流量:    1.89 MB | 最后活跃:    12340
设备: veth1_egress     | 包数:      567 | 流量:    1.89 MB | 最后活跃:    12339
```

## 技术实现

### 1. eBPF 映射

#### 设备统计映射
```rust
#[map(name = "device_stats")]
static mut DEVICE_STATS: HashMap<u32, DeviceStats> = HashMap::with_max_entries(1024, 0);
```
- 键：设备ID * 2 + 方向（0=ingress, 1=egress）
- 值：设备统计信息

#### 设备映射
```rust
#[map(name = "device_map")]
static mut DEVICE_MAP: HashMap<[u8; 16], u32> = HashMap::with_max_entries(64, 0);
```
- 键：设备名称（字节数组）
- 值：设备ID

#### 设备上下文
```rust
#[map(name = "device_context")]
static mut DEVICE_CONTEXT: HashMap<u32, u32> = HashMap::with_max_entries(1, 0);
```
- 键：0（固定）
- 值：设备ID + 方向编码

### 2. 键值生成

#### 设备统计键
```rust
fn generate_device_key(device_id: u32, is_ingress: bool) -> u32 {
    if is_ingress {
        device_id * 2
    } else {
        device_id * 2 + 1
    }
}
```

#### 设备上下文编码
```rust
let context_value = device_id | ((if is_ingress { 0 } else { 1 }) << 16);
```

### 3. 用户空间接口

#### 设置设备映射
```rust
async fn set_device_mapping(
    Extension(ebpf_manager): Extension<Arc<EbpfManager>>,
    Json(request): Json<DeviceMappingRequest>,
) -> impl IntoResponse
```

#### 设备挂载
```rust
async fn traffic_count_attach_device(
    Extension(ebpf_manager): Extension<Arc<EbpfManager>>,
    Json(request): Json<TrafficCountDeviceRequest>,
) -> impl IntoResponse
```

## 测试

### 运行测试脚本
```bash
sudo ./test_device_traffic.sh
```

### 测试场景
1. **设备映射测试**: 验证设备名称到ID的映射
2. **流量统计测试**: 验证 ingress 和 egress 流量统计
3. **多设备测试**: 验证多个设备同时监控
4. **实时更新测试**: 验证统计信息的实时更新

## 限制和注意事项

### 1. 设备数量限制
- 最多支持 64 个设备映射
- 每个设备最多支持 1024 个统计条目
- 设备名称最大长度 16 字节

### 2. 性能考虑
- 使用 eBPF 进行内核级处理
- 最小化用户空间和内核空间的交互
- 支持高并发设备监控

### 3. 内存使用
- 每个设备统计占用 24 字节
- 设备映射占用 20 字节
- 设备上下文占用 8 字节

## 故障排除

### 1. 常见问题

#### 设备未显示统计
- 检查设备是否正确挂载到TC
- 验证设备映射是否正确设置
- 确认设备有流量通过

#### 统计不准确
- 检查设备上下文是否正确设置
- 验证 ingress/egress 方向是否正确
- 确认没有重复的设备ID

#### 服务无响应
- 检查服务是否正常运行
- 验证端口 8080 是否可访问
- 确认防火墙设置

### 2. 调试方法

#### 查看日志
```bash
journalctl -u xnet -f
```

#### 检查TC规则
```bash
tc filter show dev veth0 ingress
tc filter show dev veth0 egress
```

#### 验证eBPF映射
```bash
bpftool map show
bpftool map dump id <map_id>
```

## 扩展功能

### 1. 设备分组
- 支持设备分组统计
- 按组显示流量汇总
- 支持组级别的告警

### 2. 流量告警
- 支持流量阈值告警
- 支持流量异常检测
- 支持告警通知

### 3. 历史统计
- 支持历史流量查询
- 支持流量趋势分析
- 支持统计报告生成

## 总结

设备流量统计功能为网络监控提供了强大的基础，支持多设备、双向流量的实时统计，为网络性能分析和故障诊断提供了重要支持。该功能具有良好的扩展性和性能，可以作为更复杂网络监控系统的基础组件。 