# 设备连接统计功能

## 概述

DEVICE_CONNECTION_STATS功能为每个网络设备提供详细的连接级别流量统计，支持按设备ID、端口、方向和协议进行统计，特别针对veth设备的方向处理进行了优化。

## 功能特性

### 1. 连接级别统计
- **设备维度**: 按设备ID进行统计
- **端口维度**: 记录源端口和目标端口
- **方向维度**: 区分ingress（入站）和egress（出站）
- **协议维度**: 支持TCP（6）和UDP（17）协议
- **时间维度**: 记录最后活跃时间戳

### 2. veth设备特殊处理
- **方向反转**: veth设备的ingress和egress方向会自动反转
- **智能检测**: 支持通过设备名称前缀检测veth设备
- **灵活配置**: 可以根据实际需求调整检测逻辑

### 3. 实时统计
- **包数统计**: 每个连接的总包数
- **字节统计**: 每个连接的总字节数
- **实时更新**: 基于eBPF的内核级实时统计

## 数据结构

### DeviceConnectionStats结构体
```rust
#[repr(C)]
#[derive(Debug, Clone, Copy, Zeroable, Pod)]
pub struct DeviceConnectionStats {
    pub device_id: u32,      // 设备ID
    pub src_port: u16,       // 源端口
    pub dst_port: u16,       // 目标端口
    pub direction: u32,      // 方向: 0=ingress, 1=egress
    pub protocol: u32,       // 协议: 6=TCP, 17=UDP
    pub timestamp: u64,      // 时间戳
    pub total_packets: u64,  // 总包数
    pub total_bytes: u64,    // 总字节数
}
```

## 技术实现

### 1. eBPF映射
```rust
#[map(name = "device_connection_stats")]
static mut DEVICE_CONNECTION_STATS: HashMap<u32, DeviceConnectionStats> =
    HashMap::with_max_entries(1024, 0);
```

### 2. 键值生成
```rust
fn generate_connection_key(device_id: u32, src_port: u16, dst_port: u16, direction: u32, protocol: u32) -> u32 {
    let mut key = device_id;
    key = key.wrapping_add(src_port as u32);
    key = key.wrapping_add((dst_port as u32) << 16);
    key = key.wrapping_add(direction << 24);
    key = key.wrapping_add(protocol << 28);
    key
}
```

### 3. veth设备方向调整
```rust
fn adjust_direction_for_device(device_id: u32, is_ingress: bool) -> u32 {
    if is_veth_device(device_id) {
        // 如果是veth设备，方向相反
        if is_ingress { 1 } else { 0 }
    } else {
        // 其他设备保持原方向
        if is_ingress { 0 } else { 1 }
    }
}
```

## 使用方法

### 1. 挂载设备
```bash
curl -X POST -v --noproxy '*' http://127.0.0.1:8080/traffic_count_attach_device \
  -H "Content-Type: application/json" \
  -d '{"iface": "veth0", "action": "add"}'
```

### 2. 查询所有设备连接统计
```bash
curl --noproxy '*' http://127.0.0.1:8080/traffic_device_connection_stats
```

### 3. 查询指定设备的连接统计
```bash
# 获取设备ID
DEVICE_ID=$(cat /sys/class/net/veth0/ifindex)

# 查询该设备的连接统计
curl --noproxy '*' http://127.0.0.1:8080/traffic_device_connection_stats/$DEVICE_ID
```

### 4. 移除设备监控
```bash
curl -X POST -v --noproxy '*' http://127.0.0.1:8080/traffic_count_attach_device \
  -H "Content-Type: application/json" \
  -d '{"iface": "veth0", "action": "remove"}'
```

## API接口

### 1. 查询所有设备连接统计
- **URL**: `/traffic_device_connection_stats`
- **方法**: GET
- **返回**: JSON格式的所有设备连接统计

### 2. 查询指定设备连接统计
- **URL**: `/traffic_device_connection_stats/:device_id`
- **方法**: GET
- **参数**: device_id - 设备ID
- **返回**: JSON格式的指定设备连接统计

## 输出示例

### 设备连接统计输出
```json
{
  "connection_12345": {
    "device_id": 1,
    "src_port": 8080,
    "dst_port": 54321,
    "direction": "ingress",
    "protocol": "TCP",
    "timestamp": 1234567890,
    "total_packets": 100,
    "total_bytes": 10240
  },
  "connection_67890": {
    "device_id": 1,
    "src_port": 54321,
    "dst_port": 8080,
    "direction": "egress",
    "protocol": "TCP",
    "timestamp": 1234567891,
    "total_packets": 100,
    "total_bytes": 10240
  }
}
```

## 测试

### 运行测试脚本
```bash
sudo ./test_device_connection_stats.sh
```

### 测试场景
1. **基本连接统计**: 验证TCP和UDP连接的统计
2. **veth设备测试**: 验证veth设备的方向反转
3. **多设备测试**: 验证多个设备的连接统计
4. **实时更新测试**: 验证统计信息的实时更新

## 性能考虑

### 1. 内存使用
- 每个连接统计占用32字节
- 最多支持1024个连接统计
- 总内存使用约32KB

### 2. 处理性能
- 使用eBPF进行内核级处理
- 最小化用户空间和内核空间的交互
- 支持高并发连接处理

### 3. 键值冲突
- 使用哈希算法生成键值
- 支持键值冲突处理
- 可扩展的键值生成策略

## 限制和注意事项

### 1. 连接数量限制
- 最多支持1024个连接统计
- 超出限制时会覆盖旧的统计
- 建议定期清理过期统计

### 2. 设备类型支持
- 目前主要支持veth设备的特殊处理
- 其他设备类型使用标准方向处理
- 可以根据需要扩展设备类型支持

### 3. 协议支持
- 目前支持TCP（6）和UDP（17）
- 其他协议会被忽略
- 可以根据需要扩展协议支持

## 故障排除

### 1. 常见问题

#### 连接统计不显示
- 检查设备是否正确挂载到TC
- 验证设备有TCP/UDP流量通过
- 确认连接统计映射是否正确初始化

#### veth设备方向不正确
- 检查veth设备检测逻辑
- 验证设备名称是否正确
- 确认方向调整函数是否正常工作

#### 统计数据不准确
- 检查键值生成算法
- 验证时间戳更新逻辑
- 确认包数和字节数统计

### 2. 调试方法

#### 查看eBPF日志
```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
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

### 1. 连接状态跟踪
- 支持连接状态变化跟踪
- 记录连接建立和关闭时间
- 支持连接超时处理

### 2. 流量分析
- 支持流量模式分析
- 支持异常流量检测
- 支持流量趋势分析

### 3. 告警功能
- 支持流量阈值告警
- 支持异常连接告警
- 支持告警通知

## 总结

DEVICE_CONNECTION_STATS功能为网络监控提供了细粒度的连接级别统计，特别针对veth设备的方向处理进行了优化。该功能具有良好的扩展性和性能，可以作为更复杂网络监控系统的基础组件，为网络性能分析和故障诊断提供重要支持。 