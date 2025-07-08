### add traffic count to device[TC]

curl -X POST -v --noproxy '*' http://127.0.0.1:8080/traffic_count_attach_device \
  -H "Content-Type: application/json" \
  -d '{"iface": "lo", "action": "add"}'


curl -X POST -v --noproxy '*' http://127.0.0.1:8080/traffic_count_attach_device \
  -H "Content-Type: application/json" \
  -d '{"iface": "eth0", "action": "add"}'

### query traffic count

curl --noproxy '*' http://127.0.0.1:8080/traffic_count

curl --noproxy '*' http://127.0.0.1:8080/traffic_device_state


curl --noproxy '*' http://127.0.0.1:8080/traffic_device_connection_stats
