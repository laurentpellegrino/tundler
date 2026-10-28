The VeePN updater uses headed Chrome with the Botasaurus driver to handle the
dashboard's Cloudflare challenge. The workflow also routes runner traffic through
the existing Cloudflare WARP action to avoid direct datacenter egress.

The login entry point is https://account.veepn.com/login/. Configs are accessed
through Overview → Advanced → Linux/Router, following visible controls instead
of assuming a `/en/downloads/` route. The current login email field is a text
input with `autocomplete="email"`, not an `input[type="email"]`.
See [VeePN's Linux setup instructions](https://help.veepn.com/hc/en-us/articles/19525834017810-VeePN-Linux-Setup).

The workflow reads the account login from OpenBao (`kv/vpn/veepn`, keys
`username` / `password`) through `hashicorp/vault-action` and exposes it to the
script as `VEEPN_EMAIL` / `VEEPN_PASSWORD`; no GitHub Actions secret holds the
credentials. The account login differs from per-device OpenVPN credentials. The
updater only downloads configurations; it does not generate or rotate device
credentials.
It runs daily at 05:40 UTC and can also be dispatched manually. After merging,
run **Update VeePN configs** once to verify authenticated access from the runner.
An OTP requirement or changed dashboard control causes a failure before release
publication; the previous release remains available.

To run locally with Google Chrome installed:

```sh
python3 -m venv /tmp/veepn-venv
/tmp/veepn-venv/bin/pip install -r scripts/requirements-veepn.txt
# Export VEEPN_EMAIL and VEEPN_PASSWORD securely, then:
/tmp/veepn-venv/bin/python scripts/update-veepn-configs.py --out /tmp/veepn-configs.zip
```

On a machine without a display, prefix the last command with `xvfb-run -a`.
No screenshots, cookies, or page dumps are saved by the updater.

For archive validation without account access:

```sh
python3 scripts/update-veepn-configs.py --from-zip downloaded.zip --out normalized.zip
python3 -m unittest discover -s scripts -p 'test_veepn_configs.py' -v
```

The release ZIP is flat and deterministic. Validation requires at least 100
configs, both TCP and UDP, unique provider-compatible filenames, and OpenVPN
remote directives. SHA-256 comparison detects content changes even when the
filenames and lengths stay the same; upstream ZIP ordering/timestamps do not
trigger updates.
