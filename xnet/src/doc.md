### add traffic count to device[TC]

curl -X POST -v --noproxy '*' http://127.0.0.1:8080/traffic_count_attach_device \
  -H "Content-Type: application/json" \
  -d '{"iface": "eth0", "action": "remove"}'


curl --noproxy '*' http://127.0.0.1:8080/traffic_count