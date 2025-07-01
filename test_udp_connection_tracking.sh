#!/bin/bash

# UDP连接跟踪测试脚本
# 测试eBPF程序的UDP连接跟踪功能

set -e

echo "=== UDP连接跟踪测试 ==="

# 检查是否以root权限运行
if [ "$EUID" -ne 0 ]; then
    echo "请以root权限运行此脚本"
    exit 1
fi

# 检查网络接口
INTERFACE=${1:-eth0}
if ! ip link show $INTERFACE >/dev/null 2>&1; then
    echo "错误: 网络接口 $INTERFACE 不存在"
    echo "可用的接口:"
    ip link show | grep -E "^[0-9]+:" | cut -d: -f2 | tr -d ' '
    exit 1
fi

echo "使用网络接口: $INTERFACE"

# 编译并加载eBPF程序
echo "正在编译eBPF程序..."
cargo build --release

echo "正在加载eBPF程序到接口 $INTERFACE..."

# 加载XDP程序
./target/release/xnet --iface $INTERFACE &
XNET_PID=$!

# 等待程序启动
sleep 2

echo "eBPF程序已加载，PID: $XNET_PID"

# 测试UDP连接跟踪
echo ""
echo "=== 开始UDP连接跟踪测试 ==="

# 测试1: DNS查询 (UDP 53端口)
echo "测试1: DNS查询 (UDP 53端口)"
nslookup google.com 8.8.8.8 &
DNS_PID=$!
sleep 3
kill $DNS_PID 2>/dev/null || true

# 测试2: NTP查询 (UDP 123端口)
echo "测试2: NTP查询 (UDP 123端口)"
timeout 5 ntpdate -q pool.ntp.org || true

# 测试3: 自定义UDP端口测试
echo "测试3: 自定义UDP端口测试"
# 启动一个简单的UDP服务器
nc -ul 12345 &
NC_PID=$!
sleep 1

# 发送UDP数据包
echo "test" | nc -u localhost 12345 &
sleep 2

# 清理
kill $NC_PID 2>/dev/null || true

# 测试4: 大量UDP包测试
echo "测试4: 大量UDP包测试"
for i in {1..10}; do
    echo "UDP包 $i" | nc -u localhost 12345 2>/dev/null || true
    sleep 0.1
done

echo ""
echo "=== 查看eBPF日志 ==="
# 查看eBPF日志
if command -v bpftool >/dev/null 2>&1; then
    echo "使用bpftool查看eBPF日志:"
    bpftool prog list | grep xnet || echo "未找到xnet程序"
else
    echo "bpftool未安装，无法查看详细日志"
fi

# 查看系统日志中的eBPF输出
echo ""
echo "查看系统日志中的eBPF输出:"
journalctl -f --since "1 minute ago" | grep -E "(UDP|TCP)" &
JOURNAL_PID=$!

sleep 5

# 停止日志查看
kill $JOURNAL_PID 2>/dev/null || true

echo ""
echo "=== 测试完成 ==="
echo "正在停止eBPF程序..."

# 停止eBPF程序
kill $XNET_PID 2>/dev/null || true
wait $XNET_PID 2>/dev/null || true

echo "UDP连接跟踪测试完成！"
echo ""
echo "注意事项:"
echo "1. 查看上面的日志输出，应该能看到UDP连接跟踪信息"
echo "2. 日志中应该包含 'UDP NEW' 和 'UDP DATA' 消息"
echo "3. 如果看到这些消息，说明UDP连接跟踪功能正常工作"
echo "4. 可以通过 'dmesg | grep UDP' 查看更多详细信息" 