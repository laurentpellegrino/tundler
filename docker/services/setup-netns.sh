#!/usr/bin/env bash
# Exit immediately if any command fails (strict error handling)
set -e

# ============================================================================
# TUNDLER NETWORK NAMESPACE SETUP
# ============================================================================
# This script configures Linux network namespaces to enable VPN proxy 
# functionality while maintaining API accessibility.
#
# For a detailed network architecture diagram and explanation, see:
# README.md - Architecture section
#
# Key functions:
# 1. Creates isolated VPN namespace for VPN provider services
# 2. Sets up virtual ethernet bridge between default and VPN namespaces  
# 3. Configures policy routing to route proxy traffic through VPN
# 4. Ensures tundler API remains accessible despite VPN iptables rules
# ============================================================================

# Configuration variables with defaults
# NETNS: Name of the VPN network namespace (isolated network environment)
NETNS=${TUNDLER_NETNS:-vpnns}
# HOST_VETH: Name of the virtual ethernet interface in the default namespace
HOST_VETH=${HOST_VETH:-vpn-host}
# NS_VETH: Name of the virtual ethernet interface inside the VPN namespace
NS_VETH=${NS_VETH:-vpn-ns}
# HOST_IP: IP address assigned to the host side of the veth pair
HOST_IP=${HOST_IP:-172.18.0.1}
# NS_IP: IP address assigned to the namespace side of the veth pair
NS_IP=${NS_IP:-172.18.0.2}
# SUBNET: Private subnet used for communication between namespaces (/30 = 2 hosts)
SUBNET=${SUBNET:-172.18.0.0/30}

# === CLEANUP PHASE ===
# Remove any existing network namespace with the same name (ignore errors if it doesn't exist)
ip netns del "$NETNS" 2>/dev/null || true
# Remove any existing veth interface with the same name (ignore errors if it doesn't exist)
ip link del "$HOST_VETH" 2>/dev/null || true

# === NETWORK NAMESPACE CREATION ===
# Create a new isolated network namespace for VPN traffic
ip netns add "$NETNS"
# Create a virtual ethernet pair (like a virtual cable with two ends)
# One end stays in default namespace, other end will go into VPN namespace
ip link add "$HOST_VETH" type veth peer name "$NS_VETH"
# Move the namespace end of the veth pair into the VPN namespace
ip link set "$NS_VETH" netns "$NETNS"

# === DEFAULT NAMESPACE NETWORK CONFIGURATION ===
# Assign IP address to the host side of the veth pair (/30 = point-to-point link)
ip addr add "$HOST_IP/30" dev "$HOST_VETH"
# Bring up the host side interface (make it active)
ip link set "$HOST_VETH" up

# === VPN NAMESPACE NETWORK CONFIGURATION ===
# Execute commands inside the VPN namespace to configure the namespace side
# Assign IP address to the namespace side of the veth pair
ip netns exec "$NETNS" ip addr add "$NS_IP/30" dev "$NS_VETH"
# Bring up the namespace side interface
ip netns exec "$NETNS" ip link set "$NS_VETH" up
# Bring up the loopback interface inside the namespace (required for local traffic)
ip netns exec "$NETNS" ip link set lo up
# Set default route in VPN namespace to go through the host side (enables internet access)
ip netns exec "$NETNS" ip route add default via "$HOST_IP"

# === NAT AND FORWARDING SETUP ===
# Check if NAT rule exists, if not add it (MASQUERADE hides internal IPs behind container IP)
# This allows traffic from VPN namespace to reach the internet through the default namespace
iptables -t nat -C POSTROUTING -s "$SUBNET" -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s "$SUBNET" -j MASQUERADE
# Enable IP forwarding (allows the container to route packets between namespaces)
sysctl -w net.ipv4.ip_forward=1 >/dev/null

# === PROXY TRAFFIC ROUTING SETUP ===
# This section ensures that traffic from Envoy proxy (port 8484) gets routed through the VPN
# Create a custom routing table named "vpn" with ID 200 (if it doesn't already exist)
echo "200 vpn" >> /etc/iproute2/rt_tables 2>/dev/null || true
# Route all traffic from Envoy (uid=envoy) through the VPN.
# By default, DNS queries are exempt and resolved via Docker DNS for lower latency.
# Set TUNDLER_VPN_DNS=true to also route DNS through the VPN tunnel for full privacy.
if [[ "${TUNDLER_VPN_DNS:-false}" != "true" ]]; then
    iptables -t mangle -A OUTPUT -m owner --uid-owner envoy -p udp --dport 53 -j RETURN 2>/dev/null || true
    iptables -t mangle -A OUTPUT -m owner --uid-owner envoy -p tcp --dport 53 -j RETURN 2>/dev/null || true
fi
iptables -t mangle -A OUTPUT -m owner --uid-owner envoy -j MARK --set-mark 200 2>/dev/null || true
# Create a policy routing rule: packets with mark 200 should use the "vpn" routing table
ip rule add fwmark 200 table vpn 2>/dev/null || true
# In the "vpn" routing table, set default route to go through the VPN namespace
# This ensures proxy traffic gets routed through the VPN connection
ip route add default via "$NS_IP" table vpn 2>/dev/null || true
# Keep eth0-reachable destinations from being swallowed by the VPN split
# routes. Without this, response packets (SYN-ACK, etc.) get looped back
# into the VPN tunnel instead of returning to Envoy in the default namespace.
#
# Three possible shapes for eth0's routing, depending on the container runtime:
#
#   * Docker bridge:
#       172.17.0.0/16 dev eth0 proto kernel scope link src 172.17.0.X
#     -> use the subnet as-is (1 route covers everything including the gateway).
#
#   * Kubernetes with CNIs that give the pod a /32 IP (Calico, Cilium, etc.):
#       default via 10.0.156.250 dev eth0 mtu 1370
#       10.0.156.250 dev eth0 scope link
#     -> no "proto kernel" route; must pick up the "scope link" gateway AND
#        the pod's own /32 address separately.
#
#   * Classic /24 or similar on eth0 without a kernel route:
#     -> covered by the "scope link" detection.
eth0_reachable=()
eth0_kernel=$(ip -4 route show dev eth0 proto kernel 2>/dev/null | awk '{print $1; exit}')
[[ -n "$eth0_kernel" ]] && eth0_reachable+=("$eth0_kernel")
eth0_link=$(ip -4 route show dev eth0 scope link 2>/dev/null | awk '{print $1; exit}')
[[ -n "$eth0_link" ]] && eth0_reachable+=("$eth0_link")
eth0_self=$(ip -4 addr show dev eth0 2>/dev/null | awk '/inet / {print $2; exit}')
[[ -n "$eth0_self" ]] && eth0_reachable+=("$eth0_self")

for addr in "${eth0_reachable[@]}"; do
    # Envoy's outbound packets to these destinations should still egress via
    # eth0, not the VPN (used for e.g. envoy reaching the pod's own IP stack).
    ip route add "$addr" dev eth0 table vpn 2>/dev/null || true
    # Reply packets arriving through the VPN tunnel and NAT-reversed back to
    # the pod's eth0 must exit vpnns via the veth pair, not be re-routed into
    # the tunnel by the VPN provider's 0.0.0.0/1+128.0.0.0/1 split routes.
    ip netns exec "$NETNS" ip route add "$addr" via "$HOST_IP" dev "$NS_VETH" 2>/dev/null || true
done
# MASQUERADE forwarded proxy traffic entering vpnns so the VPN tunnel sees
# its own client IP as source instead of the Docker bridge address.
# Match all interfaces except the veth pair to cover any VPN tunnel type
# (tun0 for OpenVPN, wg0-mullvad for Mullvad, nordlynx for NordVPN, etc.)
ip netns exec "$NETNS" iptables -t nat -A POSTROUTING ! -o "$NS_VETH" -j MASQUERADE 2>/dev/null || true
# Clamp TCP MSS to the path MTU on forwarded traffic entering the VPN namespace.
# VPN tunnels (tun/wg) have a lower MTU than the veth pair (1500). Without this,
# TCP SYN packets advertise an MSS too large for the tunnel, causing oversized
# segments to be silently dropped — resulting in TLS handshake failures.
ip netns exec "$NETNS" iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true

# === API AND PROXY ACCESS PROTECTION ===
# Insert rules at position 1 (highest priority) to allow external access to tundler ports
# This is necessary because VPN providers may install iptables rules that block external access
# Position 1 ensures these rules take precedence over any VPN blocking rules
iptables -I INPUT 1 -p tcp --dport 4242 -j ACCEPT 2>/dev/null || true
iptables -I INPUT 1 -p tcp --dport 8484 -j ACCEPT 2>/dev/null || true

# === DNS PROTECTION ===
# VPN providers (e.g. ExpressVPN v5) overwrite /etc/resolv.conf with their
# VPN-internal DNS servers that are only reachable from inside the tunnel.
# Envoy runs in the default namespace and needs Docker DNS to resolve upstreams.
# Solution: create a separate resolv.conf that VPN daemons bind-mount over
# /etc/resolv.conf via systemd BindPaths, leaving the real file untouched.
cp /etc/resolv.conf /etc/resolv.conf.vpnns 2>/dev/null || true

# === VPN PROVIDER NAMESPACE CONFIGURATION ===
# VPN provider systemd overrides are created during Docker build by each provider's configure.sh
# No runtime configuration needed here - the NetworkNamespacePath overrides are already in place
# This ensures VPN services run in the isolated VPN namespace, preventing their iptables rules
# from affecting the tundler API running in the default namespace
# Reload systemd to ensure all service configurations are current
systemctl daemon-reload

# === ENVOY PROXY STARTUP ===
# Check if Envoy proxy is installed and start it if available
if command -v envoy >/dev/null; then
    # Brief pause to ensure all network namespace setup operations have completed
    # This prevents race conditions where Envoy starts before routing is fully configured
    sleep 1
    
    # Start Envoy proxy as the 'envoy' user in the DEFAULT namespace
    # Key reasons for running in default namespace:
    # 1. Envoy listens on port 8484 for external connections from host
    # 2. Uses getaddrinfo DNS resolver which inherits system DNS automatically
    # 3. Outbound connections are routed through VPN via UID-based policy routing
    # 4. This setup allows external API access while routing proxy traffic through VPN
    # Running as 'envoy' user enables UID-based iptables matching for policy routing
    su -s /bin/sh envoy -c "envoy -c /etc/envoy/envoy.yaml --log-level info &"
fi
