#!/usr/bin/env bash
# Installs the MOE SOC console on the Wazuh server (the machine that runs wazuh-manager, the indexer and the dashboard).
#
#   sudo bash install-console.sh                    install or update; keeps the password and working connections
#   sudo bash install-console.sh --connect          (re)create the console's read-only Wazuh accounts
#   sudo bash install-console.sh --reset-password   choose a new console password
#   sudo bash install-console.sh --no-login         open the console without signing in (anyone who can reach the
#                                                   server on the port can then read every alert and log)
#   sudo bash install-console.sh --login            sign-in back on (the default)
#   sudo bash install-console.sh --enable-logs      archive every event, so the Logs page can search raw logs
#   sudo bash install-console.sh --disable-logs     stop archiving every event (back to Wazuh's default)
#   sudo bash install-console.sh --uninstall        remove everything this script created
#
# What it creates: system user "moe-console" (member of group wazuh, so it can READ alerts.json and the rule files),
# /opt/moe-console (the app), /etc/moe-console (its own TLS certificate, settings, password hash, connection
# secrets), /var/lib/moe-console (triage notes), the systemd service moe-console on port 8443, a read-only indexer
# user "moe_console" and a read-only Wazuh API user "moe-console".
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "Run as root: sudo bash $0"; exit 1; }

HERE="$(cd "$(dirname "$0")" && pwd)"
APP=/opt/moe-console
ETC=/etc/moe-console
STATE=/var/lib/moe-console
UNIT=/etc/systemd/system/moe-console.service
SVC_USER=moe-console
OSSEC=/var/ossec
ALERTS=$OSSEC/logs/alerts/alerts.json
PORT="${MOE_PORT:-8443}"
DASH_YML=/etc/wazuh-dashboard/opensearch_dashboards.yml
WAZUH_YML=/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml
MODE="${1:-}"

# ------------------------------------------------------------------------------------------------ raw log archiving
archive_logs() {   # $1 = on | off
  local want="$1" stamp; stamp="$(date +%Y%m%d-%H%M%S-%N)"
  [[ -f $OSSEC/etc/ossec.conf ]] || { echo "!! $OSSEC/etc/ossec.conf not found - run this on the Wazuh server"; exit 1; }
  [[ -f /etc/filebeat/filebeat.yml ]] || { echo "!! /etc/filebeat/filebeat.yml not found - is this the all-in-one Wazuh server?"; exit 1; }
  install -d -m 750 "$ETC/backups"
  cp -p $OSSEC/etc/ossec.conf "$ETC/backups/ossec.conf.$stamp"
  cp -p /etc/filebeat/filebeat.yml "$ETC/backups/filebeat.yml.$stamp"
  echo "[1/3] Backups in $ETC/backups (*.$stamp)"
  python3 -I - "$want" <<'PY'
import re, sys
on = sys.argv[1] == "on"
p = "/var/ossec/etc/ossec.conf"
s = open(p).read()
value = "yes" if on else "no"
new, n = re.subn(r"(<global>(?:(?!</global>).)*?<logall_json>)\s*(?:yes|no)\s*(</logall_json>)", rf"\g<1>{value}\g<2>", s, count=1, flags=re.S)
if n == 0:
    new = s.replace("<global>", f"<global>\n    <logall_json>{value}</logall_json>", 1)
open(p, "w").write(new)
p = "/etc/filebeat/filebeat.yml"
s = open(p).read()
new, n = re.subn(r"(\n[ \t]*archives:[ \t]*\n[ \t]*enabled:[ \t]*)(?:true|false)", rf"\g<1>{'true' if on else 'false'}", s, count=1)
if n != 1:
    sys.exit("!! could not find 'archives: enabled:' under the wazuh module in /etc/filebeat/filebeat.yml - nothing restarted")
open(p, "w").write(new)
print(f"[2/3] ossec.conf: <logall_json>{value}</logall_json>; filebeat.yml: archives enabled: {'true' if on else 'false'}")
PY
  if ! $OSSEC/bin/wazuh-analysisd -t >/dev/null 2>&1; then
    cp -p "$ETC/backups/ossec.conf.$stamp" $OSSEC/etc/ossec.conf
    cp -p "$ETC/backups/filebeat.yml.$stamp" /etc/filebeat/filebeat.yml
    echo "!! Wazuh rejected the new configuration, so both files were restored. Nothing was restarted."; exit 1
  fi
  echo "[3/3] Restarting wazuh-manager and filebeat (about 30 seconds)"
  systemctl restart wazuh-manager
  systemctl restart filebeat
  if [[ "$want" == "on" ]]; then
    echo
    echo "Done. Every event is now archived and indexed (wazuh-archives-4.x-*). Within a minute, new events are searchable"
    echo "on the console's Logs page. This uses disk space: turn it off after the evaluation with --disable-logs."
  else
    echo
    echo "Done. Events that match no rule are no longer archived. Existing wazuh-archives-* indices stay until you delete"
    echo "them (Dashboard > Indexer management > Index management)."
  fi
}

if [[ "$MODE" == "--enable-logs" ]]; then archive_logs on; exit 0; fi
if [[ "$MODE" == "--disable-logs" ]]; then archive_logs off; exit 0; fi

# ------------------------------------------------------------------------------------------------ uninstall
if [[ "$MODE" == "--uninstall" ]]; then
  if [[ -f "$ETC/console.env" && -f "$HERE/setup_accounts.py" ]]; then
    python3 -I "$HERE/setup_accounts.py" --env "$ETC/console.env" --remove --wazuh-yml "$WAZUH_YML" || true
  fi
  systemctl disable --now moe-console 2>/dev/null || true
  rm -f "$UNIT"; systemctl daemon-reload
  rm -rf "$APP" "$ETC" "$STATE"
  if id "$SVC_USER" >/dev/null 2>&1; then userdel "$SVC_USER" || echo "   note: could not remove user $SVC_USER yet; run again after a reboot"; fi
  echo "MOE console removed (raw log archiving, if you turned it on, stays on: --disable-logs turns it off)."
  exit 0
fi

# ------------------------------------------------------------------------------------------------ install / update
echo "[1/7] Checks"
command -v python3 >/dev/null || { echo "!! python3 is missing: sudo apt install python3"; exit 1; }
python3 -c 'import sys, sqlite3; sys.exit(0 if sys.version_info >= (3, 8) else 1)' || { echo "!! python3 3.8 or newer with sqlite3 is needed"; exit 1; }
getent group wazuh >/dev/null || { echo "!! group 'wazuh' not found - run this on the Wazuh server"; exit 1; }
[[ -d "$(dirname "$ALERTS")" ]] || { echo "!! $(dirname "$ALERTS") not found - run this on the Wazuh server"; exit 1; }
if ss -ltnH "( sport = :$PORT )" 2>/dev/null | grep -q . && ! systemctl is-active --quiet moe-console; then
  echo "!! Port $PORT is already used by another program. Choose another one:  sudo MOE_PORT=8444 bash $0"; exit 1
fi
IP="$(hostname -I | awk '{print $1}')"
echo "   ok (server address $IP, port $PORT)"

echo "[2/7] Service user $SVC_USER (read-only member of group wazuh)"
id "$SVC_USER" >/dev/null 2>&1 || useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin "$SVC_USER"
usermod -aG wazuh "$SVC_USER"

echo "[3/7] App files in $APP"
rm -rf "$APP"
install -d -o root -g root -m 755 "$APP"
cp -r "$HERE/app/." "$APP/"
find "$APP" -name "__pycache__" -prune -exec rm -rf {} +
chown -R root:root "$APP"
chmod -R u=rwX,go=rX "$APP"

echo "[4/7] Own TLS certificate in $ETC"
install -d -o root -g "$SVC_USER" -m 750 "$ETC"
if [[ ! -f "$ETC/cert.pem" || ! -f "$ETC/key.pem" ]]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 825 -keyout "$ETC/key.pem" -out "$ETC/cert.pem" \
    -subj "/CN=MOE SOC console" -addext "subjectAltName=IP:$IP,DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1
fi
chown root:"$SVC_USER" "$ETC/cert.pem" "$ETC/key.pem"
chmod 640 "$ETC/cert.pem" "$ETC/key.pem"

echo "[5/7] Console login (user: moe)"
HASH=""
KEEP=""
if [[ -f "$ETC/console.env" ]]; then
  KEEP="$(grep -E "^MOE_(INDEXER|API)_" "$ETC/console.env" || true)"     # working connections survive an update
  if [[ "$MODE" != "--reset-password" ]]; then
    HASH="$(sed -n "s/^MOE_PASS_HASH='\(.*\)'$/\1/p" "$ETC/console.env")"
    [[ -n "$HASH" ]] && echo "   keeping the existing password (new one: --reset-password)"
  fi
fi
if [[ -z "$HASH" ]]; then
  echo "   Choose the password for the console (at least 10 characters; it is stored only as a hash)."
  HASH="$(python3 -I "$APP/moe_console.py" --hash-password)"
fi
AUTH=on
[[ -f "$ETC/console.env" ]] && grep -q "^MOE_AUTH=off$" "$ETC/console.env" && AUTH=off
[[ "$MODE" == "--no-login" ]] && AUTH=off
[[ "$MODE" == "--login" ]] && AUTH=on
[[ "$AUTH" == "off" ]] && echo "   sign-in is OFF (--login turns it back on)"
umask 027
cat > "$ETC/console.env" <<ENV
MOE_ALERTS=$ALERTS
MOE_BIND=0.0.0.0
MOE_PORT=$PORT
MOE_CERT=$ETC/cert.pem
MOE_KEY=$ETC/key.pem
MOE_USER=moe
MOE_PASS_HASH='$HASH'
MOE_AUTH=$AUTH
MOE_STATE_DIR=$STATE
MOE_OSSEC_DIR=$OSSEC
ENV
[[ -n "$KEEP" ]] && printf '%s\n' "$KEEP" >> "$ETC/console.env"
chown root:"$SVC_USER" "$ETC/console.env"
chmod 640 "$ETC/console.env"

echo "[6/7] Read-only connections to the Wazuh indexer and server API"
INDEXER_URL="https://127.0.0.1:9200"
if [[ -f $DASH_YML ]]; then
  found="$(grep -E '^\s*opensearch\.hosts' "$DASH_YML" | grep -oE 'https://[^]"'"'"' ,]+' | head -1 || true)"
  [[ -n "$found" ]] && INDEXER_URL="$found"
fi
CA_SRC=""
for c in /etc/wazuh-dashboard/certs/root-ca.pem /etc/wazuh-indexer/certs/root-ca.pem /etc/filebeat/certs/root-ca.pem; do
  [[ -f "$c" ]] && { CA_SRC="$c"; break; }
done
if [[ -n "$CA_SRC" ]]; then
  install -o root -g "$SVC_USER" -m 640 "$CA_SRC" "$ETC/indexer-ca.pem"
else
  echo "   !! Wazuh root CA not found; the indexer connection is skipped"
fi
API_URL="https://127.0.0.1:55000"
if [[ -f $WAZUH_YML ]]; then
  u="$(sed -n 's/^\s*url:\s*["'"'"']\{0,1\}\(https\{0,1\}:\/\/[^"'"'"' ]*\).*/\1/p' "$WAZUH_YML" | head -1)"
  p="$(sed -n 's/^\s*port:\s*["'"'"']\{0,1\}\([0-9]*\).*/\1/p' "$WAZUH_YML" | head -1)"
  [[ -n "$u" ]] && API_URL="${u%/}:${p:-55000}"
  API_URL="${API_URL/\/\/localhost/\/\/127.0.0.1}"
fi
echo "   indexer $INDEXER_URL, server API $API_URL"
FORCE=""
[[ "$MODE" == "--connect" ]] && FORCE="--force"
python3 -I "$HERE/setup_accounts.py" --env "$ETC/console.env" --indexer "$INDEXER_URL" \
  ${CA_SRC:+--ca "$ETC/indexer-ca.pem"} --api "$API_URL" --wazuh-yml "$WAZUH_YML" $FORCE || \
  echo "   !! connecting failed; the live board still works. Retry with: sudo bash $0 --connect"
chown root:"$SVC_USER" "$ETC/console.env"
chmod 640 "$ETC/console.env"

echo "[7/7] Service moe-console"
install -d -o "$SVC_USER" -g "$SVC_USER" -m 750 "$STATE"
chown -R "$SVC_USER:$SVC_USER" "$STATE"
cat > "$UNIT" <<UNITFILE
[Unit]
Description=MOE SOC console (custom Wazuh front end for the pilgrim detection library)
After=network-online.target wazuh-manager.service wazuh-indexer.service

[Service]
User=$SVC_USER
Group=$SVC_USER
SupplementaryGroups=wazuh
EnvironmentFile=$ETC/console.env
ExecStart=/usr/bin/env python3 -I $APP/moe_console.py
StateDirectory=moe-console
StateDirectoryMode=0750
Restart=on-failure
RestartSec=3
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
CapabilityBoundingSet=
LockPersonality=yes

[Install]
WantedBy=multi-user.target
UNITFILE
systemctl daemon-reload
systemctl enable moe-console >/dev/null 2>&1
systemctl restart moe-console

health=""
for _ in $(seq 1 20); do
  health="$(curl -ks "https://127.0.0.1:$PORT/api/health" || true)"
  [[ -n "$health" ]] && break
  sleep 1
done
if [[ -z "$health" ]]; then
  echo "!! The console did not start. See:  journalctl -u moe-console -n 30 --no-pager"; exit 1
fi
sleep 2
health="$(curl -ks "https://127.0.0.1:$PORT/api/health" || true)"
if [[ "$health" != *'"reading_alerts": true'* ]]; then
  echo "   !! The console runs but cannot read $ALERTS yet. Check:  journalctl -u moe-console -n 30 --no-pager"
fi
# What the service itself can reach, checked as the service user with its own settings
check="$( (set -a; . "$ETC/console.env"; set +a; runuser -u "$SVC_USER" -- python3 -I "$APP/moe_console.py" --check) 2>&1 || true)"
python3 -I - "$check" <<'PY' || true
import json, sys
try:
    h = json.loads(sys.argv[1])
except Exception:
    print("   (could not run the self-check)"); sys.exit()
ix, api = h.get("indexer", {}), h.get("api", {})
line = lambda ok, text: print(f"   {'ok ' if ok else '!! '} {text}")
line(ix.get("ok"), "indexer: " + (f"OpenSearch {ix.get('version')}, newest alert {ix.get('latest_alert') or 'none'}" if ix.get("ok") else ix.get("error") or "not connected"))
if ix.get("ok"):
    line(ix.get("archives"), "raw logs: " + ("archived" if ix.get("archives") else "not archived yet (for the Logs page: sudo bash install-console.sh --enable-logs)"))
line(api.get("ok"), "server API: " + (f"Wazuh {api.get('version')}, agents {api.get('agents')}" if api.get("ok") else api.get("error") or "not connected"))
line(not h.get("rules_error"), "rule files: " + (h.get("rules_error") or f"{h.get('rules')} rules readable"))
line(h.get("triage") == "disk", "triage notes: " + ("saved in /var/lib/moe-console" if h.get("triage") == "disk" else "memory only"))
PY
if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
  echo "   Note: the ufw firewall is on. To open the console from another machine:  sudo ufw allow $PORT/tcp"
fi
echo
if [[ "$AUTH" == "off" ]]; then
  echo "Done. Open https://$IP:$PORT  (no sign-in)."
  echo "!! Sign-in is off: anyone who can reach this server on port $PORT can read every alert and log."
  echo "   Turn it back on after the demo:  sudo bash $0 --login"
else
  echo "Done. Open https://$IP:$PORT  and sign in as  moe  with the console password."
fi
echo "The browser warns about the certificate the first time (the console made its own): choose Advanced > Accept."
