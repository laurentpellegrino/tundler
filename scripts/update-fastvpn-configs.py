#!/usr/bin/env python3
"""Mirror Namecheap FastVPN's public OpenVPN config bundle and
republish just the UDP subset as a zip for our image build to pull.

Source: https://vpn.ncapi.io/groupedServerList.zip (publicly served,
no auth — confirmed in Namecheap KB 10412). Contains both tcp/ and
udp/ directories; we only use UDP (it dodges TCP-over-TCP head-of-
line blocking when we tunnel our crawler's HTTPS through it).

Output: a single fastvpn-configs.zip containing the UDP .ovpn files
flat-laid (no leading udp/ prefix), one per city. The runtime
provider reads them from /etc/fastvpn/configs/ and parses
`NCVPN-<CC>-<City>[ - Virtual]-UDP.ovpn` filenames for location
metadata. Each .ovpn has multiple `remote ...` entries — openvpn's
client-side `remote-random` already load-balances across the city's
edge IPs.

Refresh cadence: daily. Republishing is a no-op when nothing changed
(the calling workflow checksums against the current release).
"""
from __future__ import annotations

import argparse
import io
import sys
import urllib.request
import zipfile
from pathlib import Path

SOURCE_URL = "https://vpn.ncapi.io/groupedServerList.zip"


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out", type=Path, required=True,
                   help="path to write the UDP-only fastvpn-configs.zip")
    args = p.parse_args()

    print(f"fetching {SOURCE_URL}...", file=sys.stderr)
    req = urllib.request.Request(SOURCE_URL, headers={"User-Agent": "tundler-fastvpn-updater/1.0"})
    with urllib.request.urlopen(req, timeout=60) as r:
        raw = r.read()
    print(f"  upstream zip: {len(raw)} bytes", file=sys.stderr)

    udp_entries: list[tuple[str, bytes]] = []
    with zipfile.ZipFile(io.BytesIO(raw)) as src:
        for info in src.infolist():
            if not info.filename.startswith("udp/"):
                continue
            if not info.filename.endswith(".ovpn"):
                continue
            # Strip the udp/ prefix so files land directly in the
            # output zip root (consumer mounts the unpacked dir, no
            # need to nest).
            flat_name = info.filename.split("/", 1)[1]
            udp_entries.append((flat_name, src.read(info.filename)))

    if not udp_entries:
        print("ERROR: no UDP .ovpn files found in upstream zip", file=sys.stderr)
        return 1

    args.out.parent.mkdir(parents=True, exist_ok=True)
    # Sort for deterministic checksumming — same content same SHA.
    udp_entries.sort(key=lambda kv: kv[0])
    with zipfile.ZipFile(args.out, "w", zipfile.ZIP_DEFLATED, allowZip64=False) as dst:
        for name, data in udp_entries:
            # Pin timestamps to 1980-01-01 so identical content
            # produces identical bytes (zipfile.ZipInfo default
            # uses the current time, defeating our sha256 dedup).
            zi = zipfile.ZipInfo(filename=name, date_time=(1980, 1, 1, 0, 0, 0))
            zi.compress_type = zipfile.ZIP_DEFLATED
            dst.writestr(zi, data)

    countries = sorted({n.split("-")[1] for n, _ in udp_entries if n.startswith("NCVPN-")})
    print(f"wrote {len(udp_entries)} UDP configs across {len(countries)} countries → {args.out}",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
