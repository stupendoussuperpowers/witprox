#!/bin/bash

# Cleanup TPROXY rules
BUILDUSER_UID=$(id -u builduser 2>/dev/null || echo "1000")

# Remove OUTPUT marking rules
iptables -t mangle -D OUTPUT -p udp --dport 53 -m owner --uid-owner $BUILDUSER_UID -j MARK --set-mark 1 2>/dev/null || true
iptables -t mangle -D OUTPUT -p udp --dport 123 -m owner --uid-owner $BUILDUSER_UID -j MARK --set-mark 1 2>/dev/null || true
iptables -t mangle -D OUTPUT -p udp --dport 161 -m owner --uid-owner $BUILDUSER_UID -j MARK --set-mark 1 2>/dev/null || true

# Remove PREROUTING TPROXY rules
iptables -t mangle -D PREROUTING -p udp --dport 53 -m mark --mark 1 -j TPROXY --on-port 2230 --tproxy-mark 1 2>/dev/null || true
iptables -t mangle -D PREROUTING -p udp --dport 123 -m mark --mark 1 -j TPROXY --on-port 2230 --tproxy-mark 1 2>/dev/null || true
iptables -t mangle -D PREROUTING -p udp --dport 161 -m mark --mark 1 -j TPROXY --on-port 2230 --tproxy-mark 1 2>/dev/null || true

ip rule del fwmark 1 lookup 100 2>/dev/null || true
ip route del local 0.0.0.0/0 dev lo table 100 2>/dev/null || true
