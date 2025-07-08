#!/bin/bash

# 测试设备连接统计功能
echo "=== 测试设备连接统计功能 ==="

# 启动服务（如果还没有启动）
echo "1. 启动服务..."
sudo ./target/release/xnet &
SERVICE_PID=$!
sleep 3

# 等待服务启动
echo "等待服务启动..."
sleep 5

# 测试设备挂载
echo "2. 挂载设备到TC..."
curl -X POST -v --noproxy '*' http://127.0.0.1:8080/traffic_count_attach_device \
  -H "Content-Type: application/json" \
  -d '{"iface": "lo", "action": "add"}'

echo ""
echo "3. 生成一些网络流量..."
# 生成一些TCP流量
for i in {1..10}; do
    curl --noproxy '*' http://127.0.0.1:8080/ > /dev/null 2>&1
    sleep 0.1
done

# 生成一些UDP流量
for i in {1..5}; do
    echo "test" | nc -u 127.0.0.1 8080 > /dev/null 2>&1
    sleep 0.1
done

echo ""
echo "4. 查询设备连接统计..."
curl --noproxy '*' http://127.0.0.1:8080/traffic_device_connection_stats

echo ""
echo "5. 查询指定设备的连接统计..."
# 获取lo设备的ifindex
LO_DEVICE_ID=$(cat /sys/class/net/lo/ifindex)
echo "lo设备ID: $LO_DEVICE_ID"
curl --noproxy '*' http://127.0.0.1:8080/traffic_device_connection_stats/$LO_DEVICE_ID

echo ""
echo "6. 查询设备流量统计..."
curl --noproxy '*' http://127.0.0.1:8080/traffic_device_state

echo ""
echo "7. 查询总体流量统计..."
curl --noproxy '*' http://127.0.0.1:8080/traffic_count

echo ""
echo "8. 清理..."
# 移除设备
curl -X POST -v --noproxy '*' http://127.0.0.1:8080/traffic_count_attach_device \
  -H "Content-Type: application/json" \
  -d '{"iface": "lo", "action": "remove"}'

# 停止服务
kill $SERVICE_PID
wait $SERVICE_PID 2>/dev/null

echo ""
echo "=== 测试完成 ===" 