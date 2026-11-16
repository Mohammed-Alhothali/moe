#!/usr/bin/env bash
# UC04 (impossible travel) demo helper.
# Opens a temporary Cloudflare quick tunnel to the portal's sign-in pages only (nginx on 127.0.0.1:8081),
# so your phone (mobile data) and your laptop (VPN) reach the portal from two different countries.
# Close it with Ctrl+C as soon as the demo is done.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "Run as root: sudo $0"; exit 1; }
if ! command -v cloudflared >/dev/null; then
  curl -fsSL -o /tmp/cloudflared.deb \
    https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb
  dpkg -i /tmp/cloudflared.deb >/dev/null
fi
echo "Open the https://<random>.trycloudflare.com/login address printed below:"
echo "  1) on your phone using mobile data   2) on the laptop with the VPN connected (same account)"
exec cloudflared tunnel --no-autoupdate --url http://127.0.0.1:8081
