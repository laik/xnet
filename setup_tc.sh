#!/bin/bash

# 设置TC规则来启用端口流量统计
# 使用方法: ./setup_tc.sh <interface> [action]
# action: setup (默认), clean, show

INTERFACE=${1:-eth0}
ACTION=${2:-setup}

echo "TC端口流量统计设置脚本"
echo "接口: $INTERFACE"
echo "操作: $ACTION"

case $ACTION in
    "setup")
        echo "正在设置TC规则..."
        
        # 检查接口是否存在
        if ! ip link show $INTERFACE > /dev/null 2>&1; then
            echo "错误: 接口 $INTERFACE 不存在"
            exit 1
        fi
        
        # 清理现有的TC规则
        tc qdisc del dev $INTERFACE ingress 2>/dev/null || true
        
        # 添加ingress qdisc
        tc qdisc add dev $INTERFACE handle ffff: ingress
        
        # 添加eBPF程序到TC
        # 注意: 这里需要先编译并加载eBPF程序
        echo "请确保已编译并加载eBPF程序"
        echo "运行: cargo build --release"
        echo "然后运行: sudo ./target/release/xnet --iface $INTERFACE"
        
        echo "TC规则设置完成"
        echo "使用 'tc filter show dev $INTERFACE ingress' 查看规则"
        ;;
        
    "clean")
        echo "正在清理TC规则..."
        tc qdisc del dev $INTERFACE ingress 2>/dev/null || true
        echo "TC规则清理完成"
        ;;
        
    "show")
        echo "当前TC规则:"
        tc qdisc show dev $INTERFACE
        echo ""
        echo "Ingress过滤器:"
        tc filter show dev $INTERFACE ingress
        ;;
        
    *)
        echo "用法: $0 <interface> [setup|clean|show]"
        echo "  setup: 设置TC规则 (默认)"
        echo "  clean: 清理TC规则"
        echo "  show:  显示当前TC规则"
        exit 1
        ;;
esac 