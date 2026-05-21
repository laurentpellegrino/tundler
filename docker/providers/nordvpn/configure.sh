#!/usr/bin/env bash
set -e

SERVICE=nordvpnd

systemctl daemon-reload
systemctl enable "${SERVICE}" --now

# Wait briefly for the daemon to be reachable on its socket.
for _ in 1 2 3 4 5 6 7 8 9 10; do
    nordvpn status >/dev/null 2>&1 && break
    sleep 1
done

# Decline the analytics-consent prompt that nordvpn-cli started
# shipping in recent versions. Without this, every subsequent
# `nordvpn` call hangs waiting for stdin "y/n". Piping "n" once
# dismisses the prompt permanently and sets analytics to disabled,
# which is what we want operationally anyway.
echo "n" | nordvpn login 2>/dev/null || true

# Apply baseline settings BEFORE any heavy feature config fetch.
#
# meshnet off / notify off matter for memory: in the legacy
# all-providers-in-one image, nordvpnd ran inside the vpnns netns
# whose routing was blocked until tundler set up the tunnel, so the
# daemon could not reach api.nordvpn.com / downloads.nordcdn.com at
# startup — meshnet/nordwhisper/libtelio remote configs were never
# downloaded and total RSS stayed well under 600 MiB. In the VPN-hub
# architecture, nordvpnd starts in the pod's main netns with full
# internet from boot, eagerly downloading and parsing those remote
# configs unless we explicitly disable the corresponding features.
# `meshnet off` skips the meshnet runtime entirely and is the single
# biggest win; `notify off` removes the in-daemon notification ring
# buffer.
nordvpn set meshnet off || true
nordvpn set notify off || true

nordvpn set analytics disabled
nordvpn set autoconnect disabled
nordvpn set firewall disabled
nordvpn set lan-discovery enable
nordvpn set pq on
nordvpn set technology NordLynx

# Restart the daemon so it reloads with the disabled features in
# effect — otherwise meshnet/notify state stays resident from the
# initial eager load until the next pod restart.
systemctl restart "${SERVICE}"
