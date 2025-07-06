#!/usr/bin/env bash
set -e

NETNS=${TUNDLER_NETNS:-vpnns}
HOST_VETH=${HOST_VETH:-vpn-host}
NS_VETH=${NS_VETH:-vpn-ns}
HOST_IP=${HOST_IP:-172.18.0.1}
NS_IP=${NS_IP:-172.18.0.2}
SUBNET=${SUBNET:-172.18.0.0/30}

# cleanup previous namespace if exists
ip netns del "$NETNS" 2>/dev/null || true
ip link del "$HOST_VETH" 2>/dev/null || true

# create namespace and veth pair
ip netns add "$NETNS"
ip link add "$HOST_VETH" type veth peer name "$NS_VETH"
ip link set "$NS_VETH" netns "$NETNS"

ip addr add "$HOST_IP/30" dev "$HOST_VETH"
ip link set "$HOST_VETH" up

ip netns exec "$NETNS" ip addr add "$NS_IP/30" dev "$NS_VETH"
ip netns exec "$NETNS" ip link set "$NS_VETH" up
ip netns exec "$NETNS" ip link set lo up
ip netns exec "$NETNS" ip route add default via "$HOST_IP"

# enable NAT for outgoing traffic
iptables -t nat -C POSTROUTING -s "$SUBNET" -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s "$SUBNET" -j MASQUERADE
sysctl -w net.ipv4.ip_forward=1 >/dev/null

# start tinyproxy if present
if command -v tinyproxy >/dev/null; then
    ip netns exec "$NETNS" tinyproxy
fi
