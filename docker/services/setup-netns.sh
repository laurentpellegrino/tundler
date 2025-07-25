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
# Mark all TCP packets originating from port 8484 (Envoy proxy) with mark 200
# This allows us to apply special routing rules to proxy traffic
iptables -t mangle -A OUTPUT -p tcp --sport 8484 -j MARK --set-mark 200 2>/dev/null || true
# Create a policy routing rule: packets with mark 200 should use the "vpn" routing table
ip rule add fwmark 200 table vpn 2>/dev/null || true
# In the "vpn" routing table, set default route to go through the VPN namespace
# This ensures proxy traffic gets routed through the VPN connection
ip route add default via "$NS_IP" table vpn 2>/dev/null || true

# === API ACCESS PROTECTION ===
# Insert rule at position 1 (highest priority) to allow tundler API access on port 4242
# This is necessary because VPN providers may install iptables rules that block external access
# Position 1 ensures this rule takes precedence over any VPN blocking rules
iptables -I INPUT 1 -p tcp --dport 4242 -j ACCEPT 2>/dev/null || true

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
    
    # Start Envoy proxy in the DEFAULT namespace (not VPN namespace)
    # Key reasons for running in default namespace:
    # 1. Envoy listens on port 8484 for external connections from host
    # 2. Uses getaddrinfo DNS resolver which inherits system DNS automatically
    # 3. Outbound connections are routed through VPN via policy routing (fwmark 200)
    # 4. This setup allows external API access while routing proxy traffic through VPN
    envoy -c /etc/envoy/envoy.yaml --log-level info &
fi
