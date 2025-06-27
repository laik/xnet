#!/bin/bash

# 综合流量监控脚本 - 结合XDP和TC
# 用法: ./monitor_traffic.sh <interface> [start|stop|status]

INTERFACE=${1:-eth0}
ACTION=${2:-start}

# 检查是否以root权限运行
if [ "$EUID" -ne 0 ]; then
    echo "请以root权限运行此脚本"
    exit 1
fi

# 检查接口是否存在
if ! ip link show $INTERFACE > /dev/null 2>&1; then
    echo "错误: 接口 $INTERFACE 不存在"
    exit 1
fi

# 检查必要的工具
check_tools() {
    local tools=("tc" "ip" "cargo" "bpftool")
    for tool in "${tools[@]}"; do
        if ! command -v $tool > /dev/null 2>&1; then
            echo "警告: $tool 未安装"
        fi
    done
}

# 启动监控
start_monitoring() {
    echo "启动流量监控..."
    
    # 检查工具
    check_tools
    
    # 设置TC拦截
    echo "设置TC拦截规则..."
    ./setup_tc.sh $INTERFACE add
    
    # 编译并启动XDP程序
    echo "编译XDP程序..."
    cargo build --release
    
    if [ $? -ne 0 ]; then
        echo "编译失败"
        exit 1
    fi
    
    # 启动XDP程序
    echo "启动XDP程序..."
    ./target/release/xnet --iface $INTERFACE --interval 5 &
    XDP_PID=$!
    
    # 保存PID
    echo $XDP_PID > /tmp/xnet_xdp.pid
    
    echo "流量监控已启动"
    echo "XDP程序PID: $XDP_PID"
    echo "使用 './monitor_traffic.sh $INTERFACE stop' 停止监控"
}

# 停止监控
stop_monitoring() {
    echo "停止流量监控..."
    
    # 停止XDP程序
    if [ -f /tmp/xnet_xdp.pid ]; then
        XDP_PID=$(cat /tmp/xnet_xdp.pid)
        if kill -0 $XDP_PID 2>/dev/null; then
            echo "停止XDP程序 (PID: $XDP_PID)..."
            kill $XDP_PID
            wait $XDP_PID 2>/dev/null || true
        fi
        rm -f /tmp/xnet_xdp.pid
    fi
    
    # 移除TC规则
    echo "移除TC规则..."
    ./setup_tc.sh $INTERFACE remove
    
    echo "流量监控已停止"
}

# 显示状态
show_status() {
    echo "=== 流量监控状态 ==="
    
    # 检查XDP程序
    if [ -f /tmp/xnet_xdp.pid ]; then
        XDP_PID=$(cat /tmp/xnet_xdp.pid)
        if kill -0 $XDP_PID 2>/dev/null; then
            echo "XDP程序: 运行中 (PID: $XDP_PID)"
        else
            echo "XDP程序: 未运行"
            rm -f /tmp/xnet_xdp.pid
        fi
    else
        echo "XDP程序: 未运行"
    fi
    
    # 检查TC规则
    echo ""
    echo "TC规则状态:"
    ./setup_tc.sh $INTERFACE show
    
    # 显示网络接口统计
    echo ""
    echo "网络接口统计:"
    ip -s link show $INTERFACE
}

# 显示实时流量
show_realtime() {
    echo "显示实时流量统计..."
    echo "按 Ctrl+C 退出"
    
    while true; do
        clear
        echo "=== 实时流量监控 ==="
        echo "接口: $INTERFACE"
        echo "时间: $(date)"
        echo ""
        
        # 显示接口统计
        echo "接口统计:"
        ip -s link show $INTERFACE | grep -E "(RX|TX)" | head -4
        echo ""
        
        # 显示TC统计
        echo "TC统计:"
        tc -s qdisc show dev $INTERFACE | head -10
        echo ""
        
        # 显示连接统计
        echo "活跃连接:"
        ss -tuln | grep ESTAB | wc -l
        echo ""
        
        sleep 2
    done
}

case $ACTION in
    "start")
        start_monitoring
        ;;
        
    "stop")
        stop_monitoring
        ;;
        
    "status")
        show_status
        ;;
        
    "realtime")
        show_realtime
        ;;
        
    *)
        echo "用法: $0 <interface> [start|stop|status|realtime]"
        echo "  start     - 启动流量监控"
        echo "  stop      - 停止流量监控"
        echo "  status    - 显示监控状态"
        echo "  realtime  - 显示实时流量统计"
        exit 1
        ;;
esac 