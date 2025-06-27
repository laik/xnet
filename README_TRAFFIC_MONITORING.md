# XNet 流量监控系统

这是一个基于eBPF XDP和TC的综合网络流量监控系统，提供连接管理、流量统计和实时监控功能。

## 功能特性

### 1. 连接管理
- **TCP连接跟踪**: 监控TCP连接的建立、数据传输和关闭过程
- **连接状态管理**: 跟踪连接状态（建立中、已建立、关闭中、已重置）
- **连接统计**: 统计每个连接的流量数据

### 2. 流量统计
- **IP流量汇总**: 按IP地址统计流量
- **连接流量统计**: 按连接统计流量
- **实时流量监控**: 定期更新和显示流量统计

### 3. TC拦截
- **出口流量拦截**: 使用TC在出口增加流量拦截
- **流量分类**: 将流量分类到不同的队列进行监控
- **统计收集**: 收集TC层面的流量统计

## 系统架构

```
网络接口
    ↓
TC拦截层 (setup_tc.sh)
    ↓
XDP程序 (xnet-ebpf)
    ↓
用户态程序 (xnet)
    ↓
流量统计和展示
```

## 安装和编译

### 1. 环境要求
- Linux内核 5.4+
- Rust工具链
- iproute2 (tc, ip命令)
- bpftool (可选)

### 2. 编译项目
```bash
# 编译整个项目
cargo build --release

# 或者分别编译
cargo build -p xnet-ebpf --release
cargo build -p xnet --release
```

## 使用方法

### 1. 快速开始

```bash
# 启动流量监控 (需要root权限)
sudo ./monitor_traffic.sh eth0 start

# 查看监控状态
sudo ./monitor_traffic.sh eth0 status

# 查看实时流量
sudo ./monitor_traffic.sh eth0 realtime

# 停止监控
sudo ./monitor_traffic.sh eth0 stop
```

### 2. 手动使用

#### 设置TC拦截
```bash
# 添加TC拦截规则
sudo ./setup_tc.sh eth0 add

# 查看TC配置
sudo ./setup_tc.sh eth0 show

# 移除TC规则
sudo ./setup_tc.sh eth0 remove
```

#### 运行XDP程序
```bash
# 直接运行XDP程序
sudo ./target/release/xnet --iface eth0 --interval 5

# 参数说明:
# --iface: 监控的网络接口
# --interval: 统计更新间隔(秒)
```

### 3. 高级配置

#### 自定义TC规则
编辑 `setup_tc.sh` 文件，修改以下参数：
- 带宽限制: `rate 1000mbit`
- 队列数量: 修改classid
- 过滤器规则: 修改match条件

#### 自定义XDP程序
修改 `xnet-ebpf/src/main.rs` 中的：
- 连接跟踪逻辑
- 流量统计方法
- 日志输出格式

## 输出说明

### 1. 流量统计汇总
```
=== 流量统计汇总 ===
更新时间: 5.2s

--- IP流量统计 ---
IP: 192.168.1.100   | 流量: 15.67 MB
IP: 10.0.0.1        | 流量: 8.92 MB
IP: 172.16.0.5      | 流量: 3.45 MB

--- 活跃连接 ---
192.168.1.100:443 -> 10.0.0.1:52431 | 状态: 已建立 | 流量: 5.23 MB
10.0.0.1:80 -> 192.168.1.100:52432 | 状态: 已建立 | 流量: 2.15 MB

总连接数: 25
活跃连接数: 8
========================
```

### 2. 连接状态说明
- **建立中 (1)**: TCP SYN包，连接正在建立
- **已建立 (2)**: TCP连接已建立，可以传输数据
- **关闭中 (3)**: TCP FIN包，连接正在关闭
- **已重置 (4)**: TCP RST包，连接被重置

### 3. TC统计信息
```
=== Qdisc配置 ===
qdisc htb 1: dev eth0 root refcnt 2 r2q 10 default 30 direct_packets_stat 0

=== Class配置 ===
class htb 1:1 root rate 1000Mbit ceil 1000Mbit burst 1375b cburst 1375b
class htb 1:10 parent 1:1 leaf 10: prio 0 rate 1000Mbit ceil 1000Mbit burst 1375b cburst 1375b
class htb 1:30 parent 1:1 leaf 30: prio 0 rate 1000Mbit ceil 1000Mbit burst 1375b cburst 1375b
```

## 故障排除

### 1. 常见问题

#### 权限问题
```bash
# 确保以root权限运行
sudo ./monitor_traffic.sh eth0 start
```

#### 接口不存在
```bash
# 检查可用接口
ip link show

# 使用正确的接口名
sudo ./monitor_traffic.sh ens33 start
```

#### 编译错误
```bash
# 更新Rust工具链
rustup update

# 清理并重新编译
cargo clean
cargo build --release
```

### 2. 调试模式

#### 启用详细日志
```bash
# 设置日志级别
export RUST_LOG=debug

# 运行程序
sudo ./target/release/xnet --iface eth0 --interval 5
```

#### 检查eBPF程序
```bash
# 查看加载的eBPF程序
sudo bpftool prog list

# 查看eBPF maps
sudo bpftool map list
```

## 性能优化

### 1. 系统调优
```bash
# 增加内存锁定限制
ulimit -l unlimited

# 优化网络参数
echo 1 > /proc/sys/net/core/bpf_jit_enable
```

### 2. 程序优化
- 调整map大小以适应网络规模
- 优化连接键生成算法
- 减少不必要的日志输出

## 扩展开发

### 1. 添加新协议支持
在 `xnet-ebpf/src/main.rs` 中添加：
```rust
// 处理UDP
if protocol == 17 {
    handle_udp_connection(&ctx, data, data_end, ip_offset + ip_size, src_ip, dst_ip)?;
}
```

### 2. 添加新的统计维度
```rust
// 添加端口统计
#[map]
static mut PORT_STATS: HashMap<u16, u64> = HashMap::with_max_entries(1024, 0);
```

### 3. 集成其他工具
- 与Prometheus集成进行指标收集
- 与ELK Stack集成进行日志分析
- 与Grafana集成进行可视化

## 许可证

本项目采用MIT/GPL双许可证。详见LICENSE文件。 