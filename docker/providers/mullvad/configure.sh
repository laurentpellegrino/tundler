#!/usr/bin/env bash
set -e

systemctl enable mullvad-daemon --now
systemctl restart mullvad-daemon

mullvad auto-connect set off
mullvad lan set allow

systemctl restart mullvad-daemon
