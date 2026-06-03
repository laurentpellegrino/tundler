#!/usr/bin/env python3
"""Refresh the VeePN OpenVPN config archive by driving a real browser.

VeePN gates its account dashboard + API behind a Cloudflare JS challenge
(`cf-mitigated: challenge`), so a plain HTTP client (curl / requests) gets
403'd. The only reliable way to fetch the per-location configs unattended
is to drive a real Chromium that clears the challenge, logs in, and
downloads the "all configurations" archive — exactly what this does.

Flow:
  1. Launch Chromium (headed, under xvfb in CI) so Cloudflare's managed
     challenge passes (headless is reliably blocked).
  2. Log in at account.veepn.com with VEEPN_EMAIL / VEEPN_PASSWORD.
  3. Open the manual-config downloads page and trigger "download all
     configuration files".
  4. Unzip, sanity-check (>= MIN_CONFIGS .ovpn), re-zip to --out.

Env:
  VEEPN_EMAIL, VEEPN_PASSWORD   account login (NOT the manual-config creds)
Args:
  --out PATH                    output zip (default /tmp/veepn-configs.zip)

NOTE: the login-form + download-button selectors below are best-effort
(from the dashboard's visible labels). VeePN's SPA may differ or change;
if a step times out, update the selector list and re-run. This script is
intentionally verbose so a CI failure shows exactly which step broke.
"""
import argparse
import os
import sys
import tempfile
import zipfile
from pathlib import Path

from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout

LOGIN_URL = "https://account.veepn.com/en/account-auth/"
DOWNLOADS_URL = "https://account.veepn.com/en/downloads/"
MIN_CONFIGS = 100

# Best-effort selector candidates (tried in order). Update if the SPA changes.
EMAIL_SELECTORS = ['input[type="email"]', 'input[name="email"]', '#email']
PASSWORD_SELECTORS = ['input[type="password"]', 'input[name="password"]', '#password']
SUBMIT_SELECTORS = ['button[type="submit"]', 'button:has-text("Log in")', 'button:has-text("Sign in")']
# The "download all configuration files" control (cloud icon next to
# "Download all configuration files" / French "Téléchargez tous les
# fichiers de configuration").
DOWNLOAD_ALL_SELECTORS = [
    'a:has-text("all configuration")',
    'button:has-text("all configuration")',
    '[href$=".zip"]',
    'a[download]',
]


def first_visible(page, selectors, timeout=15000):
    last = None
    for sel in selectors:
        try:
            el = page.wait_for_selector(sel, timeout=timeout, state="visible")
            if el:
                return el
        except PWTimeout as e:
            last = e
    raise RuntimeError(f"none of {selectors} appeared (last: {last})")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="/tmp/veepn-configs.zip")
    args = ap.parse_args()

    email = os.environ.get("VEEPN_EMAIL")
    password = os.environ.get("VEEPN_PASSWORD")
    if not email or not password:
        print("::error::VEEPN_EMAIL / VEEPN_PASSWORD must be set", file=sys.stderr)
        return 2

    with sync_playwright() as p:
        # channel="chrome" + headed (xvfb) gives the best odds against
        # Cloudflare's managed challenge; headless chromium is blocked.
        browser = p.chromium.launch(
            headless=False,
            channel="chrome",
            args=["--disable-blink-features=AutomationControlled", "--no-sandbox"],
        )
        ctx = browser.new_context(
            user_agent=("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                        "(KHTML, like Gecko) Chrome/126.0 Safari/537.36"),
            accept_downloads=True,
            viewport={"width": 1400, "height": 1000},
        )
        # Light stealth: hide webdriver flag.
        ctx.add_init_script("Object.defineProperty(navigator,'webdriver',{get:()=>undefined})")
        page = ctx.new_page()

        print(f"[veepn] login at {LOGIN_URL}")
        page.goto(LOGIN_URL, wait_until="domcontentloaded", timeout=60000)
        page.wait_for_timeout(6000)  # let Cloudflare's challenge settle

        first_visible(page, EMAIL_SELECTORS).fill(email)
        first_visible(page, PASSWORD_SELECTORS).fill(password)
        first_visible(page, SUBMIT_SELECTORS).click()
        page.wait_for_timeout(8000)
        if "account-auth" in page.url:
            print("::error::still on the login page after submit — bad creds or selector drift", file=sys.stderr)
            print(f"[veepn] current url: {page.url}", file=sys.stderr)
            return 1
        print(f"[veepn] logged in (url={page.url})")

        print(f"[veepn] open downloads {DOWNLOADS_URL}")
        page.goto(DOWNLOADS_URL, wait_until="domcontentloaded", timeout=60000)
        page.wait_for_timeout(5000)
        # Some dashboards need the "Manual"/"Router" sub-section opened first;
        # try clicking it if present (best-effort, non-fatal).
        for label in ("Manual", "Manuel", "Router", "Routeur"):
            try:
                page.click(f'text="{label}"', timeout=3000)
                page.wait_for_timeout(2000)
            except PWTimeout:
                pass

        print("[veepn] trigger 'download all configurations'")
        with page.expect_download(timeout=60000) as dl_info:
            first_visible(page, DOWNLOAD_ALL_SELECTORS).click()
        download = dl_info.value
        raw = Path(tempfile.mkdtemp()) / (download.suggested_filename or "veepn.zip")
        download.save_as(str(raw))
        print(f"[veepn] downloaded {raw} ({raw.stat().st_size} bytes)")

        browser.close()

    # Validate + normalize: extract .ovpn, sanity-floor, re-zip flat.
    work = Path(tempfile.mkdtemp())
    with zipfile.ZipFile(raw) as zf:
        zf.extractall(work)
    ovpns = list(work.rglob("*.ovpn"))
    print(f"[veepn] archive contains {len(ovpns)} .ovpn files")
    if len(ovpns) < MIN_CONFIGS:
        print(f"::error::only {len(ovpns)} .ovpn (<{MIN_CONFIGS} floor) — refusing to publish", file=sys.stderr)
        return 1

    out = Path(args.out)
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        for f in sorted(ovpns):
            zf.write(f, arcname=f.name)  # flat, matching install.sh's expectation
    print(f"[veepn] wrote {out} ({out.stat().st_size} bytes, {len(ovpns)} configs)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
