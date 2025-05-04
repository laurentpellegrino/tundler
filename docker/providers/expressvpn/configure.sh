#!/usr/bin/env bash
set -e

# Start the ExpressVPN service
systemctl enable expressvpn-service --now

# Ensure background mode so CLI works without GUI
expressvpnctl background enable