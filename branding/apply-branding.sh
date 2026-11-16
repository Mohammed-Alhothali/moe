#!/usr/bin/env bash
# Rebrands the Wazuh dashboard as MOE: header logo, loading logo, favicon, browser title and login page.
#
# Run on the Wazuh server (where the dashboard runs), from this folder:
#     sudo bash apply-branding.sh               # uses this server's first IP address
#     sudo bash apply-branding.sh 192.168.56.128
# Undo everything:
#     sudo bash apply-branding.sh --revert
#
# Safety: opensearch_dashboards.yml is backed up first. If the dashboard does not come back within
# 3 minutes, the backup is restored and the dashboard restarted, so you never end up without a dashboard.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "Run as root: sudo bash $0"; exit 1; }

HERE="$(cd "$(dirname "$0")" && pwd)"
YML="${YML_PATH:-/etc/wazuh-dashboard/opensearch_dashboards.yml}"
ASSETS="${ASSETS_DIR:-/usr/share/wazuh-dashboard/src/core/server/core_app/assets}"
NAME="${MOE_NAME:-MOE}"
TAGLINE="${MOE_TAGLINE:-Monitor - Observe - Escalate}"
FILES="moe-logo.svg moe-logo-dark.svg moe-mark.svg moe-favicon.png moe-logo.png"
BEGIN="# MOE-BRANDING BEGIN (managed by branding/apply-branding.sh)"
END="# MOE-BRANDING END"

[[ -f "$YML" ]] || { echo "!! $YML not found - run this on the server that hosts the Wazuh dashboard."; exit 1; }
[[ -d "$ASSETS" ]] || { echo "!! $ASSETS not found - is this a Wazuh dashboard 4.x package install?"; exit 1; }

remove_block() {  # prints the yml without our block
  awk -v b="$BEGIN" -v e="$END" '$0==b{skip=1;next} $0==e{skip=0;next} !skip' "$1"
}

PORT=$(awk -F: '/^[[:space:]]*server\.port[[:space:]]*:/{gsub(/[ "\x27]/,"",$2); print $2}' "$YML" | tail -1)
PORT="${PORT:-443}"

wait_for_dashboard() {
  for _ in $(seq 1 36); do
    code=$(curl -k -s -o /dev/null -w '%{http_code}' "https://127.0.0.1:${PORT}/app/login" || true)
    [[ "$code" =~ ^(200|302)$ ]] && return 0
    sleep 5
  done
  return 1
}

restart_dashboard() {
  systemctl restart wazuh-dashboard
  echo "   waiting for the dashboard to come back (up to 3 minutes)..."
  wait_for_dashboard
}

BACKUP="${YML}.before-moe-$(date +%Y%m%d-%H%M%S)"

if [[ "${1:-}" == "--revert" ]]; then
  cp -a "$YML" "$BACKUP"
  remove_block "$BACKUP" > "$YML"
  for f in $FILES; do rm -f "$ASSETS/$f"; done
  restart_dashboard && echo "Reverted: Wazuh branding is back. (Backup: $BACKUP)" \
    || echo "!! The dashboard did not answer yet; check: systemctl status wazuh-dashboard"
  exit 0
fi

IP="${1:-$(hostname -I | awk '{print $1}')}"
BASE="https://${IP}"; [[ "$PORT" != "443" ]] && BASE="https://${IP}:${PORT}"

echo "[1/4] Check for branding settings that already exist outside this script"
clash=$(remove_block "$YML" | grep -nE '^[[:space:]]*(opensearchDashboards\.branding|opensearch_security\.(ui\.)?basicauth\.login)' || true)
if [[ -n "$clash" ]]; then
  echo "!! $YML already has branding or login-page settings (nothing was changed):"
  echo "$clash" | sed 's/^/   /'
  echo "!! Remove or comment those lines, then run this script again."
  exit 1
fi
echo "   none"

echo "[2/4] Copy the logos to the dashboard's public folder ($ASSETS)"
for f in $FILES; do install -m 644 "$HERE/assets/$f" "$ASSETS/$f"; done
owner=$(stat -c '%U:%G' "$ASSETS")
for f in $FILES; do chown "$owner" "$ASSETS/$f"; done
echo "   served at ${BASE}/ui/<file>"

echo "[3/4] Add the branding block to $YML (backup: $BACKUP)"
cp -a "$YML" "$BACKUP"
{
  remove_block "$BACKUP"
  cat <<YAML
$BEGIN
opensearchDashboards.branding:
  logo:
    defaultUrl: "${BASE}/ui/moe-logo.svg"
    darkModeUrl: "${BASE}/ui/moe-logo-dark.svg"
  mark:
    defaultUrl: "${BASE}/ui/moe-mark.svg"
    darkModeUrl: "${BASE}/ui/moe-mark.svg"
  loadingLogo:
    defaultUrl: "${BASE}/ui/moe-logo.svg"
    darkModeUrl: "${BASE}/ui/moe-logo-dark.svg"
  faviconUrl: "${BASE}/ui/moe-favicon.png"
  applicationTitle: "${NAME}"
opensearch_security.basicauth.login.title: "${NAME}"
opensearch_security.basicauth.login.subtitle: "${TAGLINE}"
opensearch_security.basicauth.login.showbrandimage: true
opensearch_security.basicauth.login.brandimage: "${BASE}/ui/moe-logo.svg"
$END
YAML
} > "$YML.new"
cat "$YML.new" > "$YML" && rm -f "$YML.new"

echo "[4/4] Restart the dashboard"
if ! restart_dashboard; then
  echo "!! The dashboard did not come back - restoring $BACKUP"
  cp -a "$BACKUP" "$YML"
  systemctl restart wazuh-dashboard
  echo "!! Restored. Send the output of:  journalctl -u wazuh-dashboard -n 50 --no-pager"
  exit 1
fi
for f in moe-logo.svg moe-mark.svg moe-favicon.png; do
  code=$(curl -k -s -o /dev/null -w '%{http_code}' "${BASE}/ui/$f" || true)
  [[ "$code" == "200" ]] && echo "   ${BASE}/ui/$f  OK" || echo "   !! ${BASE}/ui/$f answered $code - that logo will fall back to Wazuh's"
done
echo
echo "Done. Open ${BASE} and press Ctrl+F5 (the browser caches the old logo)."
echo "Then finish the in-app logos and PDF report text: see branding/README.md, step 3."
