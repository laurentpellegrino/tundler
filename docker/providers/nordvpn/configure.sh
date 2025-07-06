#!/usr/bin/env bash
set -e

systemctl enable nordvpnd --now

nordvpn set analytics disabled
nordvpn set lan-discovery enable
nordvpn set pq on
nordvpn set technology NordLynx
