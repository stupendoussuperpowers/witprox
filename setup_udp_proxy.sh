#!/bin/bash

# Basic iptables rules for UDP TPROXY
# Run as root

# Get builduser UID
BUILDUSER_UID=$(id -u builduser 2>/dev/null || echo "1000")

# Mark packets from builduser in OUTPUT chain (ignore if already exists)
iptables -t mangle -A OUTPUT -p udp --dport 53 -m owner --uid-owner $BUILDUSER_UID -j MARK --set-mark 1 2>/dev/null || true
iptables -t mangle -A OUTPUT -p udp --dport 123 -m owner --uid-owner $BUILDUSER_UID -j MARK --set-mark 1 2>/dev/null || true
iptables -t mangle -A OUTPUT -p udp --dport 161 -m owner --uid-owner $BUILDUSER_UID -j MARK --set-mark 1 2>/dev/null || true

# TPROXY rules in PREROUTING (only for marked packets, ignore if already exists)
iptables -t mangle -A PREROUTING -p udp --dport 53 -m mark --mark 1 -j TPROXY --on-port 2230 --tproxy-mark 1 2>/dev/null || true
iptables -t mangle -A PREROUTING -p udp --dport 123 -m mark --mark 1 -j TPROXY --on-port 2230 --tproxy-mark 1 2>/dev/null || true
iptables -t mangle -A PREROUTING -p udp --dport 161 -m mark --mark 1 -j TPROXY --on-port 2230 --tproxy-mark 1 2>/dev/null || true

# Route marked packets to localhost (ignore if already exists)
ip rule add fwmark 1 lookup 100 2>/dev/null || true
ip route add local 0.0.0.0/0 dev lo table 100 2>/dev/null || true
