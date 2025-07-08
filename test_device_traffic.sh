#!/bin/bash

# 设备流量统计测试脚本
# 使用方法: ./test_device_traffic.sh

echo "=== 设备流量统计测试 ==="

# 检查是否以root权限运行
if [ "$EUID" -ne 0 ]; then
    echo "请以root权限运行此脚本"
    exit 1
fi

# 检查服务是否运行
if ! curl -s http://127.0.0.1:8080/ > /dev/null; then
    echo "错误: 服务未运行，请先启动服务"
    exit 1
fi

echo "1. 挂载设备到TC..."
curl -X POST -v --noproxy '*' http://127.0.0.1:8080/traffic_count_attach_device \
  -H "Content-Type: application/json" \
  -d '{"iface": "veth0", "action": "add"}'

echo ""
echo "2. 挂载另一个设备到TC..."
curl -X POST -v --noproxy '*' http://127.0.0.1:8080/traffic_count_attach_device \
  -H "Content-Type: application/json" \
  -d '{"iface": "veth1", "action": "add"}'

echo ""
echo "3. 生成一些测试流量..."

# 创建测试网络命名空间
ip netns add test1 2>/dev/null || true
ip netns add test2 2>/dev/null || true

# 创建veth对
ip link add veth0 type veth peer name veth0-peer 2>/dev/null || true
ip link add veth1 type veth peer name veth1-peer 2>/dev/null || true

# 配置网络
ip link set veth0 up
ip link set veth1 up
ip addr add 10.0.1.1/24 dev veth0 2>/dev/null || true
ip addr add 10.0.2.1/24 dev veth1 2>/dev/null || true

# 将peer端移到命名空间
ip link set veth0-peer netns test1 2>/dev/null || true
ip link set veth1-peer netns test2 2>/dev/null || true

# 配置命名空间内的网络
ip netns exec test1 ip link set veth0-peer up
ip netns exec test1 ip addr add 10.0.1.2/24 dev veth0-peer 2>/dev/null || true
ip netns exec test2 ip link set veth1-peer up
ip netns exec test2 ip addr add 10.0.2.2/24 dev veth1-peer 2>/dev/null || true

# 生成一些测试流量
echo "生成测试流量..."
for i in {1..5}; do
    echo "测试 $i: 从test1到test2的ping"
    ip netns exec test1 ping -c 3 10.0.2.2 > /dev/null 2>&1
    
    echo "测试 $i: 从test2到test1的ping"
    ip netns exec test2 ping -c 3 10.0.1.2 > /dev/null 2>&1
    
    sleep 1
done

echo ""
echo "4. 查询流量统计..."
curl --noproxy '*' http://127.0.0.1:8080/traffic_count

echo ""
echo "5. 清理测试环境..."
curl -X POST -v --noproxy '*' http://127.0.0.1:8080/traffic_count_attach_device \
  -H "Content-Type: application/json" \
  -d '{"iface": "veth0", "action": "remove"}'

curl -X POST -v --noproxy '*' http://127.0.0.1:8080/traffic_count_attach_device \
  -H "Content-Type: application/json" \
  -d '{"iface": "veth1", "action": "remove"}'

# 清理网络命名空间
ip netns del test1 2>/dev/null || true
ip netns del test2 2>/dev/null || true

echo ""
echo "=== 测试完成 ===" 