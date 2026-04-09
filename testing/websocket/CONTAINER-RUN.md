# Container Run Notes

Use `testing/websocket/node-a-tun-container.yaml` when running the FIPS node
inside Docker or Podman for browser testing.

What the container needs:

- `CAP_NET_ADMIN`
- `/dev/net/tun`
- IPv6 enabled (`net.ipv6.conf.all.disable_ipv6=0`)
- a published host port for the WebSocket server: `8080/tcp`

What is exposed to the host:

- `8080/tcp` only

Recommended run style:

- override the image entrypoint to run only `fips`
- do not use the default test image entrypoint (it also starts sshd, dnsmasq, iperf, and an HTTP server)
