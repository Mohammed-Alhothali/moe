#!/usr/bin/env bash
# Rifadah Pilgrim Services Portal - installer for the Ubuntu web server (web01, runs the Wazuh agent).
# Usage (from this folder):  sudo ./setup.sh
# Re-running is safe: it updates the code and keeps the existing database and secret key.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "Run as root: sudo $0"; exit 1; }
HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$(dirname "$HERE")"
APP=/opt/pilgrim-portal

echo "[1/9] Packages (python3-venv, nginx, auditd)"
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3-venv nginx auditd curl >/dev/null

echo "[2/9] Service account 'portal'"
id portal &>/dev/null || useradd --system --home-dir "$APP" --shell /usr/sbin/nologin portal

echo "[3/9] Application files"
install -d -o root -g root -m 755 "$APP" "$APP/app" "$APP/public" "$APP/geo"
cp -r "$SRC/app.py" "$SRC/seed.py" "$SRC/requirements.txt" "$SRC/templates" "$APP/app/"
rm -rf "$APP/public/static" && cp -r "$SRC/static" "$APP/public/static"
install -d -o portal -g portal -m 750 "$APP/data" "$APP/data/documents"
install -d -o portal -g adm -m 750 /var/log/pilgrim-portal
touch /var/log/pilgrim-portal/portal.log
chown portal:adm /var/log/pilgrim-portal/portal.log && chmod 640 /var/log/pilgrim-portal/portal.log

echo "[4/9] Python virtual environment"
[[ -x "$APP/venv/bin/python" ]] || python3 -m venv "$APP/venv"
"$APP/venv/bin/pip" install -q --upgrade pip
"$APP/venv/bin/pip" install -q -r "$APP/app/requirements.txt"

echo "[5/9] Configuration (/etc/pilgrim-portal.env)"
if [[ ! -f /etc/pilgrim-portal.env ]]; then
  cat > /etc/pilgrim-portal.env <<CONF
PORTAL_ORG="Rifadah Pilgrim Services"
PORTAL_SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
PORTAL_DB=$APP/data/portal.db
PORTAL_LOG=/var/log/pilgrim-portal/portal.log
PORTAL_DOCS=$APP/data/documents
PORTAL_GEO_DB=$APP/geo/country.mmdb
PORTAL_LAB_COUNTRY=SA
PORTAL_GEO_ONLINE=1
CONF
  chown root:portal /etc/pilgrim-portal.env && chmod 640 /etc/pilgrim-portal.env
fi

echo "[6/9] Database with synthetic pilgrims"
runuser -u portal -- env PORTAL_DB="$APP/data/portal.db" "$APP/venv/bin/python" "$APP/app/seed.py"

echo "[7/9] Country database (DB-IP Lite, CC BY 4.0)"
if [[ ! -s "$APP/geo/country.mmdb" ]]; then
  for month in "$(date +%Y-%m)" "$(date -d '-1 month' +%Y-%m)"; do
    if curl -fsSL "https://download.db-ip.com/free/dbip-country-lite-$month.mmdb.gz" -o /tmp/dbip.mmdb.gz; then
      gunzip -c /tmp/dbip.mmdb.gz > "$APP/geo/country.mmdb" && rm -f /tmp/dbip.mmdb.gz && break
    fi
  done
  [[ -s "$APP/geo/country.mmdb" ]] && echo "   installed" || echo "   not downloaded - the portal will ask ip-api.com instead"
fi

echo "[8/9] gunicorn service + nginx"
cp "$HERE/pilgrim-portal.service" /etc/systemd/system/pilgrim-portal.service
cp "$HERE/nginx-pilgrim-portal.conf" /etc/nginx/sites-available/pilgrim-portal
ln -sf /etc/nginx/sites-available/pilgrim-portal /etc/nginx/sites-enabled/pilgrim-portal
rm -f /etc/nginx/sites-enabled/default
nginx -t
systemctl daemon-reload
systemctl enable --now pilgrim-portal >/dev/null
systemctl restart pilgrim-portal nginx

echo "[9/9] auditd: record commands executed by the web tier (UC07)"
sed -e "s/@WWW_UID@/$(id -u www-data)/g" -e "s/@PORTAL_UID@/$(id -u portal)/g" \
    "$HERE/audit-pilgrim-portal.rules" > /etc/audit/rules.d/pilgrim-portal.rules
systemctl enable --now auditd >/dev/null
augenrules --load >/dev/null 2>&1 || auditctl -R /etc/audit/rules.d/pilgrim-portal.rules
auditctl -l | grep -c pp_web_exec | xargs -I{} echo "   {} audit rules loaded (key pp_web_exec)"

IP=$(hostname -I | awk '{print $1}')
cat <<DONE

Portal ready:  http://$IP/
Audit log:     /var/log/pilgrim-portal/portal.log   (tail -f it during the demo)
Lab accounts:  pilgrim0042 / Pilgrim#2026   agency.in01 / Agency#2026   staff.ops01 / Staff#2026
               fin.approver01 / Finance#2026   portal.admin / Admin#2026
Next:          on the Wazuh manager run  wazuh/deploy_manager.sh  (rules + agent config)
DONE
