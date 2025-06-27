#!/bin/bash

# TC拦截脚本 - 在出口增加流量拦截
# 用法: ./setup_tc.sh <interface> [action]
# action: add/remove/show

INTERFACE=${1:-eth0}
ACTION=${2:-add}

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

case $ACTION in
    "add")
        echo "在接口 $INTERFACE 上添加TC拦截规则..."
        
        # 删除现有的qdisc（如果存在）
        tc qdisc del dev $INTERFACE root 2>/dev/null || true
        
        # 添加HTB qdisc作为根qdisc
        tc qdisc add dev $INTERFACE root handle 1: htb default 30
        
        # 创建根类
        tc class add dev $INTERFACE parent 1: classid 1:1 htb rate 1000mbit
        
        # 创建默认类（用于正常流量）
        tc class add dev $INTERFACE parent 1:1 classid 1:30 htb rate 1000mbit
        
        # 创建监控类（用于拦截和分析）
        tc class add dev $INTERFACE parent 1:1 classid 1:10 htb rate 1000mbit
        
        # 添加过滤器，将所有流量重定向到监控类
        tc filter add dev $INTERFACE protocol ip parent 1:0 prio 1 u32 \
            match ip dst 0.0.0.0/0 flowid 1:10
        
        # 添加统计过滤器
        tc filter add dev $INTERFACE protocol ip parent 1:0 prio 2 u32 \
            match ip src 0.0.0.0/0 flowid 1:10
        
        echo "TC拦截规则已添加"
        ;;
        
    "remove")
        echo "移除接口 $INTERFACE 上的TC规则..."
        tc qdisc del dev $INTERFACE root 2>/dev/null || true
        echo "TC规则已移除"
        ;;
        
    "show")
        echo "显示接口 $INTERFACE 的TC配置:"
        echo "=== Qdisc配置 ==="
        tc qdisc show dev $INTERFACE
        echo ""
        echo "=== Class配置 ==="
        tc class show dev $INTERFACE
        echo ""
        echo "=== Filter配置 ==="
        tc filter show dev $INTERFACE
        echo ""
        echo "=== 统计信息 ==="
        tc -s qdisc show dev $INTERFACE
        tc -s class show dev $INTERFACE
        ;;
        
    *)
        echo "用法: $0 <interface> [add|remove|show]"
        echo "  add    - 添加TC拦截规则"
        echo "  remove - 移除TC拦截规则"
        echo "  show   - 显示TC配置和统计"
        exit 1
        ;;
esac 