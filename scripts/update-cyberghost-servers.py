#!/usr/bin/env python3
"""Generate a fresh CyberGhost servers.json by bulk-DNS-resolving every
candidate hostname under the *.cg-dialup.net domain.

Why this works without any CyberGhost API auth:
CyberGhost's OpenVPN edge follows a fixed naming pattern —
{groupID}-{countryCode}.cg-dialup.net. A daily DNS sweep of every
(groupID × country-code) combination tells us exactly which ones
the provider currently operates: the ones that resolve to an A
record exist, the others (NXDOMAIN) don't. No login flow, no
session cookies, no CAPTCHA risk. This is the same approach gluetun
uses in their cyberghost provider updater
(github.com/qdm12/gluetun/tree/master/internal/provider/cyberghost).

Output JSON shape (UTF-8, sorted by country then hostname):
    [
      {"country": "Germany", "hostname": "87-1-de.cg-dialup.net"},
      {"country": "Germany", "hostname": "87-8-de.cg-dialup.net"},
      ...
    ]

The hostname's group prefix:
  87-1   = Premium UDP    (default)
  87-8   = NoSpy UDP      (Romania-hosted, special-tier servers)
  87-19  = Gaming UDP
  97-1   = Premium TCP    (we don't use, but included for parity)
  97-8   = NoSpy TCP
  97-19  = Gaming TCP

Our .ovpn template uses proto=udp on port 443, so any of the
groupIDs work at runtime — the prefix only signals which CyberGhost
backend tier serves the connection.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import socket
import sys
from pathlib import Path

# ISO-3166 alpha-2 codes (lowercase) for European countries CyberGhost
# is known to operate in. Anywhere outside this list gets skipped
# even if DNS resolves — keeps the rotator pool geo-bounded to the
# region the operator wants exits in.
EUROPE_COUNTRY_CODES: dict[str, str] = {
    "al": "Albania",
    "ad": "Andorra",
    "at": "Austria",
    "by": "Belarus",
    "be": "Belgium",
    "ba": "Bosnia and Herzegovina",
    "bg": "Bulgaria",
    "hr": "Croatia",
    "cy": "Cyprus",
    "cz": "Czech Republic",
    "dk": "Denmark",
    "ee": "Estonia",
    "fi": "Finland",
    "fr": "France",
    "ge": "Georgia",
    "de": "Germany",
    "gr": "Greece",
    "hu": "Hungary",
    "is": "Iceland",
    "ie": "Ireland",
    "im": "Isle of Man",
    "it": "Italy",
    "lv": "Latvia",
    "li": "Liechtenstein",
    "lt": "Lithuania",
    "lu": "Luxembourg",
    "mk": "Macedonia",
    "mt": "Malta",
    "md": "Moldova",
    "mc": "Monaco",
    "me": "Montenegro",
    "nl": "Netherlands",
    "no": "Norway",
    "pl": "Poland",
    "pt": "Portugal",
    "ro": "Romania",
    "rs": "Serbia",
    "sk": "Slovakia",
    "si": "Slovenia",
    "es": "Spain",
    "se": "Sweden",
    "ch": "Switzerland",
    "ua": "Ukraine",
    "gb": "United Kingdom",
}

# UDP-tier group IDs only. Our cyberghost.go generates `proto udp`
# configs; the TCP-tier variants (97-*) would still connect over
# UDP/443 but signal the wrong intent and might land us on
# differently-configured edges. Stick to UDP backends.
UDP_GROUP_IDS = ("87-1", "87-8", "87-19")


def candidates() -> list[tuple[str, str]]:
    """Returns (country_name, hostname) pairs to probe."""
    out: list[tuple[str, str]] = []
    for cc, country in EUROPE_COUNTRY_CODES.items():
        for gid in UDP_GROUP_IDS:
            out.append((country, f"{gid}-{cc}.cg-dialup.net"))
    return out


def resolves(host: str, timeout_sec: float = 3.0) -> bool:
    """True if `host` returns at least one A record within timeout_sec."""
    socket.setdefaulttimeout(timeout_sec)
    try:
        socket.gethostbyname(host)
        return True
    except (socket.gaierror, socket.herror, socket.timeout):
        return False


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out", type=Path, required=True,
                   help="path to write the resulting servers.json")
    p.add_argument("--workers", type=int, default=64,
                   help="parallel DNS workers (default 64)")
    args = p.parse_args()

    probes = candidates()
    print(f"probing {len(probes)} candidate hostnames...", file=sys.stderr)

    keep: list[dict[str, str]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(resolves, h): (country, h) for country, h in probes}
        for fut in concurrent.futures.as_completed(futures):
            country, host = futures[fut]
            try:
                if fut.result():
                    keep.append({"country": country, "hostname": host})
            except Exception as exc:
                print(f"  probe error for {host}: {exc}", file=sys.stderr)

    keep.sort(key=lambda e: (e["country"], e["hostname"]))

    args.out.write_text(json.dumps(keep, indent=2, ensure_ascii=False) + "\n")
    print(f"wrote {len(keep)} servers across {len({e['country'] for e in keep})} countries → {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
