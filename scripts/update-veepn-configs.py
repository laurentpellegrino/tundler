#!/usr/bin/env python3
"""Mirror VeePN configs using the Botasaurus Chrome driver.

Requires Google Chrome and requirements-veepn.txt; use xvfb-run in CI.
VEEPN_EMAIL / VEEPN_PASSWORD are account credentials, not VPN device credentials.
Follows Overview -> Linux/Router -> download all without generating credentials.
"""
from __future__ import annotations

import argparse
import os
import re
import sys
import tempfile
import time
import zipfile
from pathlib import Path

LOGIN_URL = "https://account.veepn.com/login/"
MIN_CONFIGS = 100
CONFIG_NAME = re.compile(r"^[a-z0-9-]+\.(tcp|udp)\.veepn\.com\.ovpn$")


def wait_for(check, description: str, timeout: float = 60):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = check()
        if result:
            return result
        time.sleep(0.5)
    raise RuntimeError(f"Timed out waiting for {description}")


def visible_element(driver, selector: str):
    for element in driver.select_all(selector, wait=None):
        if element.run_js("(el) => !!el.getClientRects().length && !el.disabled"):
            return element
    return None


def settled(driver, selector: str, description: str, action, attempts: int = 6):
    """Run `action` on a visible element once the dashboard stops re-rendering it.

    The login form is hydrated client-side after the Cloudflare check, so the
    first node matching `selector` is often replaced moments later and acting
    on it raises DetachedElementException. Re-resolve and retry until the same
    node survives a short settle window.
    """
    from botasaurus_driver.exceptions import DetachedElementException

    for _ in range(attempts):
        element = wait_for(lambda: visible_element(driver, selector), description)
        time.sleep(1)
        try:
            if not element.run_js("(el) => el.isConnected"):
                continue
            result = action(element)
        except DetachedElementException:
            continue
        if result is not False:
            return element
    raise RuntimeError(f"{description} kept re-rendering")


def fill(driver, selector: str, description: str, value: str):
    def action(element):
        element.click()
        element.type(value)
        # A re-render can swallow typed text; verify before moving on.
        return element.run_js("(el) => el.value") == value
    return settled(driver, selector, description, action)


def control(driver, labels: tuple[str, ...] = (), *, archive: bool = False):
    """Find a visible control by label, excluding unrelated downloads."""
    found = driver.run_js(r"""
        document.querySelectorAll('[data-tundler-control]').forEach(
            e => e.removeAttribute('data-tundler-control'));
        const elements = [...document.querySelectorAll('a, button, [role="button"]')];
        const matches = elements.filter(e => {
            if (!e.getClientRects().length || e.disabled) return false;
            const text = (e.innerText || e.textContent || e.getAttribute('aria-label') || '')
                .trim().replace(/\s+/g, ' ').toLowerCase();
            return args.labels.includes(text) || (args.archive &&
                /download.*all.*(config|location)|all.*config.*(file|download)/.test(text));
        });
        // The dashboard offers the archive for Linux and for Router; the
        // Linux one is the OpenVPN set the tunnel image expects.
        const match = matches.find(e => e.href && /\/linux\//.test(e.href)) || matches[0];
        if (match) match.setAttribute('data-tundler-control', 'true');
        return !!match;
    """, args={"labels": list(labels), "archive": archive})
    return driver.select('[data-tundler-control="true"]', wait=None) if found else None


def logged_in(driver) -> bool:
    # A redirect alone is not proof of authentication (e.g. OTP / error pages):
    # require a logout control, or the dashboard's own sections rendered with
    # no password prompt on the page.
    return bool(driver.run_js(r"""
        const text = e => (e.innerText || e.getAttribute('aria-label') || '').trim();
        const controls = [...document.querySelectorAll('a[href], button')];
        const logout = controls.some(e => /^(log ?out|sign ?out)$/i.test(text(e))
            || (e.href && /\/(logout|sign-out)\/?$/.test(new URL(e.href).pathname)));
        const dashboard = !document.querySelector('input[type="password"]')
            && [...document.querySelectorAll('h1, h2')].some(h => /^(overview|my devices)$/i.test(text(h)));
        return document.querySelector('meta[name="meta-auth"]')?.content === '1' || logout || dashboard;
    """))


def completed_download(directory: Path):
    files = [p for p in directory.iterdir()
             if p.is_file() and not p.name.endswith((".crdownload", ".tmp"))]
    if any(directory.glob("*.crdownload")):
        return None
    if len(files) > 1:
        raise RuntimeError("Expected one configuration archive download")
    if files:
        if not zipfile.is_zipfile(files[0]):
            raise ValueError("Downloaded file is not a ZIP archive")
        return files[0]
    return None


def download_archive(directory: Path, email: str, password: str) -> Path:
    from botasaurus_driver import Driver, cdp

    driver = Driver(headless=False, lang="en-US", window_size=(1400, 1000))
    try:
        print(f"[veepn] opening {LOGIN_URL}", flush=True)
        driver.google_get(LOGIN_URL, bypass_cloudflare=True)
        fill(driver, 'input[autocomplete="email"], input[type="email"]', "login email field", email)
        fill(driver, 'input[type="password"]', "login password field", password)
        settled(driver, 'button[type="submit"]', "login submit button", lambda el: el.click())
        wait_for(lambda: logged_in(driver), "authenticated dashboard; check credentials or OTP")
        print("[veepn] authenticated; locating manual configurations", flush=True)

        # Follow rendered navigation instead of guessing a /downloads/ URL.
        overview = control(driver, ("overview",))
        if overview:
            overview.click()

        target = wait_for(lambda: control(driver, archive=True)
                          or control(driver, ("linux", "router")),
                          "Linux/Router configuration control")
        # Find again because control() marks the selected element for clicking.
        download = control(driver, archive=True)
        if download is None:
            target = control(driver, ("linux", "router"))
            if target is None:
                raise RuntimeError("Manual configuration control disappeared")
            target.click()
            download = wait_for(lambda: control(driver, archive=True),
                                "download all configuration files control")
        driver.run_cdp_command(cdp.browser.set_download_behavior(
            behavior="allow", download_path=str(directory.resolve())))
        print("[veepn] downloading all configurations", flush=True)
        download.click()
        return wait_for(lambda: completed_download(directory), "completed ZIP download", timeout=120)
    finally:
        driver.close()


def normalize_archive(raw: Path, out: Path) -> int:
    """Validate and flatten configs with stable ordering, timestamps and bytes."""
    entries: dict[str, bytes] = {}
    protocols = set()
    with zipfile.ZipFile(raw) as source:
        for info in source.infolist():
            if info.is_dir() or not info.filename.endswith(".ovpn"):
                continue
            name = info.filename.rsplit("/", 1)[-1]
            match = CONFIG_NAME.fullmatch(name)
            if not match:
                raise ValueError(f"Unexpected OpenVPN filename: {name!r}")
            if name in entries:
                raise ValueError(f"Duplicate flattened config: {name}")
            data = source.read(info)
            if not re.search(rb"(?m)^\s*remote\s+\S+", data):
                raise ValueError(f"Config has no OpenVPN remote directive: {name}")
            entries[name] = data
            protocols.add(match[1])
    if len(entries) < MIN_CONFIGS or protocols != {"tcp", "udp"}:
        raise ValueError(f"Expected >= {MIN_CONFIGS} TCP+UDP configs; "
                         f"got {len(entries)} with protocols {sorted(protocols)}")

    out.parent.mkdir(parents=True, exist_ok=True)
    # No upstream paths are extracted. Replace output only after successful writing.
    with tempfile.TemporaryDirectory(dir=out.parent) as work:
        fresh = Path(work) / "configs.zip"
        with zipfile.ZipFile(fresh, "w", zipfile.ZIP_DEFLATED) as dest:
            for name, data in sorted(entries.items()):
                info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                dest.writestr(info, data)
        fresh.replace(out)
    return len(entries)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path("/tmp/veepn-configs.zip"))
    parser.add_argument("--from-zip", type=Path,
                        help="validate/normalize a downloaded archive without logging in")
    args = parser.parse_args()
    try:
        if args.from_zip:
            count = normalize_archive(args.from_zip, args.out)
        else:
            email, password = os.environ.get("VEEPN_EMAIL"), os.environ.get("VEEPN_PASSWORD")
            if not email or not password:
                print("::error::VEEPN_EMAIL / VEEPN_PASSWORD must be set", file=sys.stderr)
                return 2
            with tempfile.TemporaryDirectory(prefix="veepn-") as work:
                raw = download_archive(Path(work), email, password)
                count = normalize_archive(raw, args.out)
        print(f"[veepn] wrote {count} configs to {args.out}")
        return 0
    except Exception as error:
        # Browser exceptions can contain form values. Do not dump page state or traces.
        print(f"::error::VeePN refresh failed ({type(error).__name__}); "
              "existing release retained.", file=sys.stderr)
        if isinstance(error, (ValueError, zipfile.BadZipFile)) or (
                isinstance(error, RuntimeError) and str(error).startswith("Timed out waiting for")):
            print(str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
