# UDP连接跟踪功能实现

## 概述

本项目实现了基于eBPF的UDP连接跟踪功能，能够实时监控和跟踪UDP数据包的传输，为网络流量分析提供支持。

## 功能特性

### 1. UDP头部解析
- 解析UDP数据包的源端口、目标端口、长度和校验和
- 支持IPv4协议的UDP数据包处理
- 边界检查确保内存安全

### 2. 连接跟踪
- 为每个UDP"连接"生成唯一的连接标识符
- 跟踪双向连接（源到目标和目标到源）
- 区分新连接和数据传输

### 3. 流量统计
- 记录每个连接的字节数统计
- 支持IP级别的流量统计
- 实时更新连接状态

### 4. 日志记录
- 记录UDP连接的建立和数据传输
- 提供详细的调试信息
- 支持不同级别的日志输出

## 实现细节

### UDP头部结构体

```rust
#[repr(C, packed)]
pub struct UdpHdr {
    pub source: u16,    // 源端口
    pub dest: u16,      // 目标端口
    pub len: u16,       // UDP长度
    pub check: u16,     // 校验和
}
```

### 连接跟踪逻辑

```rust
fn handle_udp_connection(
    ctx: &XdpContext,
    data: usize,
    data_end: usize,
    udp_offset: usize,
    src_ip: u32,
    dst_ip: u32,
) -> Result<(), ()> {
    // 1. 边界检查
    let udp_size = core::mem::size_of::<UdpHdr>();
    if data + udp_offset + udp_size > data_end {
        return Err(());
    }

    // 2. 解析UDP头部
    let udphdr = (data + udp_offset) as *const UdpHdr;
    let src_port = unsafe { (*udphdr).source };
    let dst_port = unsafe { (*udphdr).dest };

    // 3. 生成连接标识符
    let conn_key = generate_conn_key(src_ip, dst_ip, src_port, dst_port);
    let reverse_conn_key = generate_conn_key(dst_ip, src_ip, dst_port, src_port);

    // 4. 更新统计信息
    let packet_size = (data_end - data) as u64;
    update_connection_stats(conn_key, packet_size)?;

    // 5. 连接状态跟踪
    let existing_conn = unsafe { CONNECTION_TRACK.get(&conn_key) };
    let reverse_conn = unsafe { CONNECTION_TRACK.get(&reverse_conn_key) };

    if existing_conn.is_none() && reverse_conn.is_none() {
        // 新连接
        unsafe {
            let _ = CONNECTION_TRACK.insert(&conn_key, &2, 0);
            let _ = CONNECTION_TRACK.insert(&reverse_conn_key, &2, 0);
        }
        debug!(ctx, "UDP NEW: {}:{} -> {}:{} (ESTABLISHED)", ...);
    } else {
        // 数据传输
        debug!(ctx, "UDP DATA: {}:{} -> {}:{} (DATA)", ...);
    }

    Ok(())
}
```

### 连接标识符生成

```rust
fn generate_conn_key(src_ip: u32, dst_ip: u32, src_port: u16, dst_port: u16) -> u64 {
    let src_ip_u64 = src_ip as u64;
    let dst_ip_u64 = dst_ip as u64;
    let src_port_u64 = src_port as u64;
    let dst_port_u64 = dst_port as u64;

    // 组合IP和端口形成64位连接键
    (src_ip_u64 << 32) | dst_ip_u64 | (src_port_u64 << 48) | (dst_port_u64 << 32)
}
```

## 数据结构

### 连接跟踪映射
```rust
#[map]
static mut CONNECTION_TRACK: HashMap<u64, u32> = HashMap::with_max_entries(8192, 0);
```
- 键：64位连接标识符
- 值：连接状态（2表示已建立）

### 连接统计映射
```rust
#[map]
static mut CONNECTION_STATS: HashMap<u64, u64> = HashMap::with_max_entries(8192, 0);
```
- 键：64位连接标识符
- 值：累计字节数

### IP统计映射
```rust
#[map]
static mut IP_STATS: HashMap<u32, u64> = HashMap::with_max_entries(1024, 0);
```
- 键：32位IP地址
- 值：累计字节数

## 使用方法

### 1. 编译程序
```bash
cargo build --release
```

### 2. 运行程序
```bash
sudo ./target/release/xnet --iface eth0
```

### 3. 运行测试
```bash
sudo ./test_udp_connection_tracking.sh
```

## 测试场景

### 1. DNS查询测试
- 使用nslookup进行DNS查询
- 验证UDP 53端口的连接跟踪

### 2. NTP查询测试
- 使用ntpdate进行时间同步查询
- 验证UDP 123端口的连接跟踪

### 3. 自定义端口测试
- 使用netcat创建UDP服务器和客户端
- 验证自定义端口的连接跟踪

### 4. 大量数据包测试
- 发送多个UDP数据包
- 验证连接统计的准确性

## 日志输出示例

```
UDP NEW: 192.168.1.100:12345 -> 8.8.8.8:53 (ESTABLISHED)
UDP DATA: 8.8.8.8:53 -> 192.168.1.100:12345 (DATA)
UDP DATA: 192.168.1.100:12345 -> 8.8.8.8:53 (DATA)
```

## 性能考虑

### 1. 内存使用
- 连接跟踪映射最多支持8192个连接
- IP统计映射最多支持1024个IP地址
- 每个连接占用16字节内存

### 2. 处理性能
- 使用eBPF进行内核级处理
- 最小化用户空间和内核空间的交互
- 支持高并发连接处理

### 3. 扩展性
- 可以通过调整映射大小来支持更多连接
- 支持添加更多统计维度
- 可以集成到更大的网络监控系统中

## 限制和注意事项

### 1. UDP特性
- UDP是无连接协议，连接跟踪基于IP和端口组合
- 不跟踪连接状态变化（如TCP的SYN、ACK等）
- 连接超时需要外部机制处理

### 2. 内存限制
- eBPF映射大小有限制
- 需要定期清理过期连接
- 考虑内存碎片化问题

### 3. 安全性
- 所有内存访问都有边界检查
- 使用unsafe块进行必要的底层操作
- 错误处理确保程序稳定性

## 未来改进

### 1. 连接超时机制
- 实现基于时间的连接清理
- 支持可配置的超时时间
- 添加连接生命周期管理

### 2. 更多统计维度
- 添加包计数统计
- 支持时间窗口统计
- 实现流量速率计算

### 3. 用户空间接口
- 提供用户空间API查询统计信息
- 支持实时监控和告警
- 实现配置管理接口

### 4. 性能优化
- 优化连接键生成算法
- 减少内存分配和释放
- 实现批量处理机制

## 总结

UDP连接跟踪功能为网络监控和分析提供了强大的基础。通过eBPF技术，我们能够在内核层面高效地跟踪UDP连接，为网络安全、性能监控和故障诊断提供支持。

该实现具有良好的扩展性和性能，可以作为更复杂网络监控系统的基础组件。 