#!/bin/bash
set -e

# Create namespaces
for ns in pc1 device1 device2 pc2; do
    ip netns add "$ns"
    ip -n "$ns" link set lo up
done

# Create virtual Ethernet pairs
ip link add veth-pc1 type veth peer name veth-d1a
ip link add veth-d1b type veth peer name veth-d2a
ip link add veth-d2b type veth peer name veth-pc2

# Assign interfaces to namespaces
ip link set veth-pc1 netns pc1
ip link set veth-d1a netns device1
ip link set veth-d1b netns device1
ip link set veth-d2a netns device2
ip link set veth-d2b netns device2
ip link set veth-pc2 netns pc2

# Configure IP addresses
ip -n pc1 addr add 10.0.1.1/24 dev veth-pc1
ip -n device1 addr add 10.0.1.2/24 dev veth-d1a
ip -n device1 addr add 10.0.2.1/24 dev veth-d1b
ip -n device2 addr add 10.0.2.2/24 dev veth-d2a
ip -n device2 addr add 10.0.3.1/24 dev veth-d2b
ip -n pc2 addr add 10.0.3.2/24 dev veth-pc2

# Activate interfaces
ip -n pc1 link set veth-pc1 up
ip -n device1 link set veth-d1a up
ip -n device1 link set veth-d1b up
ip -n device2 link set veth-d2a up
ip -n device2 link set veth-d2b up
ip -n pc2 link set veth-pc2 up

# Configure routes
ip -n pc1 route add default via 10.0.1.2
ip -n pc2 route add default via 10.0.3.1
ip -n device1 route add 10.0.3.0/24 via 10.0.2.2
ip -n device2 route add 10.0.1.0/24 via 10.0.2.1

# Enable forwarding
ip netns exec device1 sysctl -w net.ipv4.ip_forward=1
ip netns exec device2 sysctl -w net.ipv4.ip_forward=1

echo "Network setup completed!"
