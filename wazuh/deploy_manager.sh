#!/usr/bin/env bash
# Installs the pilgrim detection library on the Wazuh manager, validates it, and restarts the manager.
# Anything that fails validation is rolled back automatically.
# Usage (from this folder):  sudo ./deploy_manager.sh
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "Run as root: sudo $0"; exit 1; }
HERE="$(cd "$(dirname "$0")" && pwd)"
OSSEC="${OSSEC_DIR:-/var/ossec}"
CONF="$OSSEC/etc/ossec.conf"
AGENT_CONF="$OSSEC/etc/shared/default/agent.conf"
PY="$OSSEC/framework/python/bin/python3"; [[ -x "$PY" ]] || PY=python3
BACKUP="$OSSEC/backup-pilgrim-lab-$(date +%Y%m%d-%H%M%S)"

echo "[0/5] Check that none of this library's rule IDs is already used on the manager"
ours=$(grep -hoE '<rule[^>]*[[:space:]]id="[0-9]+"' "$HERE"/rules/pp-*.xml | grep -oE '[0-9]+' | sort -u)
existing=$(find "$OSSEC/etc/rules" -name '*.xml' ! -name 'pp-*' -print0 | xargs -0 -r grep -HoE '<rule[^>]*[[:space:]]id="[0-9]+"' 2>/dev/null || true)
clash=""
for id in $ours; do
  where=$(printf '%s\n' "$existing" | grep -F "id=\"$id\"" | cut -d: -f1 | sort -u | tr '\n' ' ' || true)
  [[ -n "$where" ]] && clash+="   rule $id already exists in: $where"$'\n'
done
if [[ -n "$clash" ]]; then
  echo "!! Rule ID collision - nothing was changed:"
  printf '%s' "$clash"
  echo "!! Wazuh keeps only the first rule with a given ID, so the library's rule would be silently ignored."
  echo "!! Renumber or remove the rules listed above, then run this script again."
  exit 1
fi
echo "   no collisions ($(echo "$ours" | wc -l) rule IDs checked)"

mkdir -p "$BACKUP"/{decoders,rules,lists}
cp -a "$CONF" "$BACKUP/ossec.conf"
[[ -f "$AGENT_CONF" ]] && cp -a "$AGENT_CONF" "$BACKUP/agent.conf"
for d in decoders rules lists; do cp -a "$OSSEC"/etc/$d/pp-* "$BACKUP/$d/" 2>/dev/null || true; done
rollback() {
  trap - ERR
  echo "!! Something failed - restoring the previous configuration from $BACKUP"
  for d in decoders rules lists; do
    rm -f "$OSSEC"/etc/$d/pp-*
    cp -a "$BACKUP"/$d/pp-* "$OSSEC/etc/$d/" 2>/dev/null || true
  done
  cp -a "$BACKUP/ossec.conf" "$CONF"
  [[ -f "$BACKUP/agent.conf" ]] && cp -a "$BACKUP/agent.conf" "$AGENT_CONF"
  echo "!! Nothing was restarted. Fix the error above and run the script again."
  exit 1
}
# From here on, any failing command restores the backup before the script stops.
trap rollback ERR

echo "[1/5] Decoders, rules and CDB lists"
install -o wazuh -g wazuh -m 660 "$HERE"/decoders/pp-*.xml "$OSSEC/etc/decoders/"
install -o wazuh -g wazuh -m 660 "$HERE"/rules/pp-*.xml "$OSSEC/etc/rules/"
install -o wazuh -g wazuh -m 660 "$HERE"/lists/pp-* "$OSSEC/etc/lists/"
ls "$HERE"/decoders/pp-*.xml "$HERE"/rules/pp-*.xml "$HERE"/lists/pp-* | sed 's|.*/|   |'

echo "[2/5] Register the CDB lists in ossec.conf"
for f in "$HERE"/lists/pp-*; do
  name=$(basename "$f")
  if ! grep -q "<list>etc/lists/$name</list>" "$CONF"; then
    sed -i "0,/<\/ruleset>/s|</ruleset>|  <list>etc/lists/$name</list>\n  </ruleset>|" "$CONF"
    echo "   + $name"
  fi
done

echo "[3/5] Centralized agent configuration (group 'default')"
mkdir -p "$(dirname "$AGENT_CONF")"
[[ -f "$AGENT_CONF" ]] || printf '<agent_config>\n</agent_config>\n' > "$AGENT_CONF"
"$PY" - "$AGENT_CONF" "$HERE/agent/agent.conf" <<'PYCODE'
import re, sys
target, block = sys.argv[1], open(sys.argv[2]).read().strip() + "\n"
text = open(target).read()
pattern = re.compile(r"<!-- PILGRIM-LAB BEGIN.*?<!-- PILGRIM-LAB END -->\n?", re.S)
# A function replacement: the block contains Windows paths (C:\PilgrimShare) whose backslashes
# must not be read as regex escapes.
text = pattern.sub(lambda m: block, text) if pattern.search(text) else text.rstrip("\n") + "\n\n" + block
open(target, "w").write(text)
PYCODE
chown wazuh:wazuh "$AGENT_CONF" && chmod 660 "$AGENT_CONF"

echo "[4/5] Validate ruleset and agent configuration"
"$OSSEC/bin/wazuh-analysisd" -t || rollback
if [[ -x "$OSSEC/bin/verify-agent-conf" ]]; then "$OSSEC/bin/verify-agent-conf" -f "$AGENT_CONF" || rollback; fi

echo "[5/5] Restart the manager"
trap - ERR
systemctl restart wazuh-manager
echo
echo "Done. Backup of the previous configuration: $BACKUP"
echo "Run the regression suite from the project folder:  sudo $PY tests/run_on_manager.py"
