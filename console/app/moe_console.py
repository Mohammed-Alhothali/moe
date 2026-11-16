#!/usr/bin/env python3
"""MOE SOC console: a custom front end for Wazuh, built around the pilgrim detection library.

Pages (a single-page app in static/): Live board, Overview, Alerts, Logs, Agents, ATT&CK, Use cases.

Where the data comes from (all read-only):
  * alerts.json on the manager      followed live for the board          (the service user is in group wazuh)
  * the Wazuh indexer (OpenSearch)   search, histograms, statistics      (its own read-only indexer account)
  * the Wazuh server API             agents, SCA, manager status         (its own API user with the readonly role)
  * the manager's rule files         rule XML for the rule viewer        (group wazuh)
The only thing it writes is its own triage notes, in SQLite under /var/lib/moe-console.

Security notes
  * Every alert and log field is attacker-controlled (command lines, URLs, usernames). The API returns JSON and the
    page renders text only (never as HTML), under a strict Content-Security-Policy.
  * The browser never talks to the indexer or the API. Index names, fields and query shapes are fixed here; what
    a user types only becomes a query_string or wildcard value inside the Wazuh alert and archive indices.
  * Triage changes need the login, a JSON body, a custom header and a same-origin Origin, so another web site
    cannot forge them through the browser's saved login.
  * Standard library only: nothing to pip-install on the Wazuh server.

Settings (environment; the installer writes them to /etc/moe-console/console.env):
  MOE_ALERTS     alert file to follow             (default /var/ossec/logs/alerts/alerts.json)
  MOE_BIND       address to listen on             (default 0.0.0.0)
  MOE_PORT       port                             (default 8443)
  MOE_CERT/KEY   TLS certificate and key          (required unless MOE_PLAIN_HTTP=1, which is for local tests only)
  MOE_USER       login name                       (default moe)
  MOE_PASS_HASH  pbkdf2_sha256$<iterations>$<salt b64>$<hash b64>   (made by:  moe_console.py --hash-password)
  MOE_KEEP       alerts kept in memory for the board (default 5000)
  MOE_AUTH       on (default) or off: off removes the sign-in, so anyone who can reach the port reads everything
  MOE_INDEXER_URL, MOE_INDEXER_USER, MOE_INDEXER_PASS, MOE_INDEXER_CA (or MOE_INDEXER_PIN)
  MOE_API_URL, MOE_API_USER, MOE_API_PASS, MOE_API_PIN   (SHA-256 of the API certificate, taken at install time)
  MOE_STATE_DIR  triage database                  (default /var/lib/moe-console)
  MOE_OSSEC_DIR  Wazuh directory                  (default /var/ossec)
"""
import base64, collections, csv, getpass, hashlib, hmac, http.client, io, json, os, re, secrets, sqlite3, ssl, sys
import threading, time, traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, urlencode, urlparse

VERSION = "4.0"
HERE = os.path.dirname(os.path.abspath(__file__))
STATIC = os.path.join(HERE, "static")
env = os.environ.get
ALERTS = env("MOE_ALERTS", "/var/ossec/logs/alerts/alerts.json")
KEEP = int(env("MOE_KEEP", "5000"))
OSSEC_DIR = env("MOE_OSSEC_DIR", "/var/ossec")
STATE_DIR = env("MOE_STATE_DIR", "/var/lib/moe-console")
INDEX = {"alerts": env("MOE_ALERTS_INDEX", "wazuh-alerts-*"), "logs": env("MOE_ARCHIVES_INDEX", "wazuh-archives-*")}
VULN_INDEX = env("MOE_VULN_INDEX", "wazuh-states-vulnerabilities-*")
AUTH_OFF = env("MOE_AUTH", "on").strip().lower() == "off"
DEMO = env("MOE_DEMO", "").strip() == "1"      # demo/run_demo.py: sample data from a local stand-in, never a real server
MAX_STR = 4000
MAX_WINDOW = 10000                      # OpenSearch's default index.max_result_window
STATIC_TYPES = {".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8", ".js": "text/javascript; charset=utf-8",
                ".json": "application/json; charset=utf-8", ".svg": "image/svg+xml", ".png": "image/png",
                ".woff2": "font/woff2", ".txt": "text/plain; charset=utf-8"}
CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; "
       "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'; object-src 'none'")

CATALOGUE = json.load(open(os.path.join(STATIC, "usecases.json"), encoding="utf-8"))
# Only rules that raise visible alerts; silent classifiers and tuning rules never reach alerts.json anyway.
RULE_UC = {r["id"]: uc["n"] for uc in CATALOGUE["usecases"] for r in uc["rules"] if not r["silent"] and not r["tuning"]}
UC_RULES = {uc["n"]: [r["id"] for r in uc["rules"] if not r["silent"] and not r["tuning"]] for uc in CATALOGUE["usecases"]}
OUR_RULES = sorted(RULE_UC)

SEVERITY = [{"key": "low", "to": 7}, {"key": "med", "from": 7, "to": 12}, {"key": "high", "from": 12, "to": 15},
            {"key": "crit", "from": 15}]
RANGES = {"15m": 900, "1h": 3600, "4h": 14400, "24h": 86400, "7d": 604800, "30d": 2592000}
INTERVALS = [("10s", 10), ("30s", 30), ("1m", 60), ("2m", 120), ("5m", 300), ("10m", 600), ("30m", 1800), ("1h", 3600),
             ("3h", 10800), ("6h", 21600), ("12h", 43200), ("1d", 86400)]
FIELD_RE = re.compile(r"^[A-Za-z0-9_@][A-Za-z0-9_.@-]{0,127}$")
AGENT_ID = re.compile(r"^\d{3,6}$")
# A search is read as Lucene syntax when it names a field (rule.id:..., agent.name:...), quotes a phrase, groups with
# brackets or uses AND / OR / NOT. Everything else is a plain-words search, so a Windows path like C:\Users\Public
# is not mistaken for a field called "C".
FIELD_SYNTAX = re.compile(r'(?:^|[\s(!+-])(?:[A-Za-z_@][\w@-]*(?:\.[\w@-]+)+|id|location|full_log|timestamp|decoder|'
                          r'agent|rule|data|syscheck|manager|predecoder|input|previous_output|_id|_index):')
LUCENE_HINT = re.compile(r'["()]|\b(?:AND|OR|NOT)\b')
# Plain-text searches look for the words inside these fields (case-insensitive), plus a phrase match on full_log.
CONTAINS_FIELDS = [
    "rule.description", "rule.id", "agent.name", "location", "decoder.name", "syscheck.path",
    "data.srcip", "data.srcuser", "data.dstuser", "data.username", "data.url", "data.command", "data.event",
    "data.audit.exe", "data.audit.command", "data.win.system.message", "data.win.system.eventID",
    "data.win.eventdata.commandLine", "data.win.eventdata.image", "data.win.eventdata.parentImage",
    "data.win.eventdata.originalFileName", "data.win.eventdata.targetFilename", "data.win.eventdata.queryName",
    "data.win.eventdata.targetUserName", "data.win.eventdata.subjectUserName", "data.win.eventdata.serviceName",
    "data.win.eventdata.imagePath", "data.win.eventdata.targetObject", "data.win.eventdata.user"]
SUMMARY_FIELDS = ["timestamp", "id", "rule.id", "rule.level", "rule.description", "rule.mitre", "agent.id", "agent.name",
                  "agent.ip", "location", "syscheck.path", "syscheck.event"]
FACETS = {"alerts": [("agent.name", 8), ("rule.id", 8), ("rule.mitre.tactic", 8), ("rule.groups", 10)],
          "logs": [("agent.name", 8), ("decoder.name", 8), ("location", 8)]}
EXPORT_COLUMNS = {
    "alerts": ["timestamp", "agent.name", "agent.ip", "rule.id", "rule.level", "rule.description", "rule.mitre.id",
               "location", "full_log", "id"],
    "logs": ["timestamp", "agent.name", "location", "decoder.name", "rule.id", "rule.description", "full_log", "id"]}
KEY_DAEMONS = ["wazuh-analysisd", "wazuh-remoted", "wazuh-db", "wazuh-modulesd", "wazuh-apid", "wazuh-authd",
               "wazuh-execd", "wazuh-logcollector", "wazuh-monitord", "wazuh-syscheckd"]


# ----------------------------------------------------------------------------------------------- small helpers
def hash_password(password, iterations=310000):
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return f"pbkdf2_sha256${iterations}${base64.b64encode(salt).decode()}${base64.b64encode(digest).decode()}"


def check_password(password, stored):
    try:
        algo, iterations, salt, digest = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        calc = hashlib.pbkdf2_hmac("sha256", password.encode(), base64.b64decode(salt), int(iterations))
        return hmac.compare_digest(calc, base64.b64decode(digest))
    except Exception:
        return False


def clip(value):
    """Copy of a document with every long string cut, so one huge event cannot bloat the console."""
    if isinstance(value, str):
        return value if len(value) <= MAX_STR else value[:MAX_STR] + " [cut]"
    if isinstance(value, dict):
        return {k: clip(v) for k, v in value.items()}
    if isinstance(value, list):
        return [clip(v) for v in value[:200]]
    return value


def one(q, key, default=""):
    values = q.get(key)
    return values[0] if values else default


def as_int(text, default, low, high, what):
    try:
        value = int(text) if text not in ("", None) else default
    except ValueError:
        raise Problem(400, f"{what} must be a number.")
    return max(low, min(high, value))


def dig(doc, path, default=None):
    for part in path.split("."):
        if not isinstance(doc, dict):
            return default
        doc = doc.get(part)
    return default if doc is None else doc


def uc_of(rule_id):
    rid = str(rule_id or "")
    if rid in RULE_UC:
        return RULE_UC[rid]
    if re.fullmatch(r"11(0[1-9]|1\d|2[0-5])\d\d", rid):
        return int(rid[2:4])
    return None


class Problem(Exception):
    """An error with an HTTP status and a message written for the person using the console."""

    def __init__(self, status, message, **extra):
        super().__init__(message)
        self.status, self.message, self.extra = status, message, extra


# ----------------------------------------------------------------------------------------------- upstream HTTPS
class Upstream:
    """Minimal HTTPS JSON client (standard library) for the Wazuh indexer and the Wazuh server API."""

    def __init__(self, name, url, ca="", pin="", timeout=25):
        u = urlparse(url)
        # Plain HTTP is accepted in one case only: demo mode talking to the stand-in on this machine.
        self.plain = DEMO and u.scheme == "http" and u.hostname in ("127.0.0.1", "localhost")
        if (u.scheme != "https" and not self.plain) or not u.hostname:
            raise ValueError(f"{name}: the address must look like https://127.0.0.1:9200")
        self.name, self.host, self.port, self.base = name, u.hostname, u.port or 443, u.path.rstrip("/")
        self.timeout = timeout
        self.pin = (pin or "").lower().replace(":", "")
        if self.plain:
            self.pin, self.ctx = "", None
            return
        if ca:
            ctx = ssl.create_default_context(cafile=ca)
            ctx.check_hostname = False          # verify the chain against the Wazuh root CA, as the Wazuh dashboard does
            # Python 3.13+ adds strict RFC 5280 checks by default; the root CA made by wazuh-certs-tool has no keyUsage
            # extension, which strict mode rejects. The chain and signatures are still verified.
            ctx.verify_flags &= ~getattr(ssl, "VERIFY_X509_STRICT", 0)
        else:
            if not self.pin:
                raise ValueError(f"{name}: needs a CA file or a pinned certificate fingerprint")
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE     # trust comes from the pinned fingerprint, checked before any credential
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        self.ctx = ctx

    def request(self, method, path, body=None, headers=None, timeout=None):
        if self.plain:
            conn = http.client.HTTPConnection(self.host, self.port, timeout=timeout or self.timeout)
        else:
            conn = http.client.HTTPSConnection(self.host, self.port, context=self.ctx, timeout=timeout or self.timeout)
        try:
            conn.connect()
            if self.pin:
                der = conn.sock.getpeercert(binary_form=True) or b""
                if not hmac.compare_digest(hashlib.sha256(der).hexdigest(), self.pin):
                    raise Problem(502, f"The {self.name} presented a different certificate than at install time. If it "
                                       "was renewed on purpose, run: sudo bash install-console.sh --connect", setup="cert")
            hdrs = {"Accept": "application/json", "Connection": "close", **(headers or {})}
            data = None
            if body is not None:
                data = json.dumps(body).encode("utf-8")
                hdrs["Content-Type"] = "application/json"
            conn.request(method, self.base + path, body=data, headers=hdrs)
            resp = conn.getresponse()
            raw = resp.read(64 * 1024 * 1024)
            try:
                payload = json.loads(raw.decode("utf-8", "replace")) if raw else {}
            except ValueError:
                payload = {"text": raw[:500].decode("utf-8", "replace")}
            return resp.status, payload
        except Problem:
            raise
        except ssl.SSLCertVerificationError as e:
            raise Problem(502, f"The {self.name} certificate is not signed by the expected CA ({e.verify_message}).")
        except (OSError, http.client.HTTPException) as e:
            raise Problem(502, f"Cannot reach the {self.name} at {self.host}:{self.port} ({e.__class__.__name__}).")
        finally:
            conn.close()


def opensearch_reason(payload):
    """The most specific reason in an OpenSearch error body (query syntax errors live deep in failed_shards)."""
    err = payload.get("error") if isinstance(payload, dict) else None
    if isinstance(err, str):
        return err[:400]
    if not isinstance(err, dict):
        return str(payload)[:400]
    best = err.get("reason") or err.get("type") or "error"
    chains = [s.get("reason") for s in err.get("failed_shards") or []][:1] + [err.get("caused_by")] + \
             [(err.get("root_cause") or [None])[0]]
    for node in chains:
        while isinstance(node, dict):
            best = node.get("reason") or best
            node = node.get("caused_by")
        if best and best != "all shards failed":
            break
    return str(best)[:400]


class Indexer:
    def __init__(self):
        self.up, self.error = None, None
        url = env("MOE_INDEXER_URL", "")
        if url:
            try:
                self.up = Upstream("Wazuh indexer", url, ca=env("MOE_INDEXER_CA", ""), pin=env("MOE_INDEXER_PIN", ""))
            except (ValueError, OSError, ssl.SSLError) as e:
                self.error = f"Indexer settings are not usable: {e}"
        token = base64.b64encode(f"{env('MOE_INDEXER_USER', '')}:{env('MOE_INDEXER_PASS', '')}".encode()).decode()
        self.auth = {"Authorization": "Basic " + token}

    def call(self, method, path, body=None):
        if not self.up:
            raise Problem(503, self.error or "The console is not connected to the Wazuh indexer yet. On the Wazuh "
                                             "server run: sudo bash install-console.sh --connect", setup="indexer")
        status, payload = self.up.request(method, path, body, self.auth)
        if status == 401:
            raise Problem(502, "The Wazuh indexer rejected the console's account. Run: sudo bash install-console.sh "
                               "--connect", setup="indexer")
        if status == 403:
            raise Problem(502, "The console's indexer account may not read this data: " + opensearch_reason(payload),
                          setup="indexer")
        if status >= 400:
            raise Problem(400 if status == 400 else 502, opensearch_reason(payload))
        return payload

    def search(self, kind, body):
        index = INDEX.get(kind, kind)
        return self.call("POST", f"/{quote(index, safe='*,')}/_search?ignore_unavailable=true&allow_no_indices=true", body)


class WazuhApi:
    def __init__(self):
        self.up, self.error = None, None
        url = env("MOE_API_URL", "")
        if url:
            try:
                self.up = Upstream("Wazuh server API", url, pin=env("MOE_API_PIN", ""))
            except ValueError as e:
                self.error = f"API settings are not usable: {e}"
        self.basic = base64.b64encode(f"{env('MOE_API_USER', '')}:{env('MOE_API_PASS', '')}".encode()).decode()
        self.token, self.token_until = None, 0.0
        self.lock = threading.Lock()
        self.cache = {}

    def _token(self, force=False):
        with self.lock:
            if force or not self.token or time.time() > self.token_until:
                status, payload = self.up.request("POST", "/security/user/authenticate",
                                                  headers={"Authorization": "Basic " + self.basic})
                if status != 200:
                    raise Problem(502, "The Wazuh server API rejected the console's API user. Run: sudo bash "
                                       "install-console.sh --connect", setup="api")
                self.token = (payload.get("data") or {}).get("token")
                self.token_until = time.time() + 600          # tokens live 900 s by default
            return self.token

    def get(self, path, params=None, ttl=10):
        if not self.up:
            raise Problem(503, self.error or "The console is not connected to the Wazuh server API yet. On the Wazuh "
                                             "server run: sudo bash install-console.sh --connect", setup="api")
        target = path + ("?" + urlencode(sorted(params.items())) if params else "")
        hit = self.cache.get(target)
        if hit and hit[0] > time.time():
            return hit[1]
        status, payload = 0, {}
        for attempt in (0, 1):
            status, payload = self.up.request("GET", target, headers={"Authorization": "Bearer " + self._token(attempt == 1)})
            if status != 401:
                break
        if status == 429:
            raise Problem(502, "The Wazuh server API is limiting requests; try again in a minute.")
        if status != 200:
            detail = (payload.get("detail") or payload.get("title") or "") if isinstance(payload, dict) else ""
            raise Problem(502, f"The Wazuh server API answered {status} for {path}. {detail}"[:300])
        data = payload.get("data") or {}
        if len(self.cache) > 300:
            self.cache.clear()
        self.cache[target] = (time.time() + ttl, data)
        return data


# ----------------------------------------------------------------------------------------------- rule files
RULE_BLOCK = re.compile(r"""<rule\s[^>]*?\bid\s*=\s*["'](\d+)["'][^>]*>.*?</rule>""", re.S)


class RuleBook:
    """Rule id -> its XML, read from the manager's own rule files (Wazuh's ruleset and /var/ossec/etc/rules)."""

    def __init__(self):
        self.dirs = [("ruleset/rules", os.path.join(OSSEC_DIR, "ruleset", "rules")),
                     ("etc/rules", os.path.join(OSSEC_DIR, "etc", "rules"))]
        self.index, self.loaded, self.error = {}, 0.0, None
        self.lock = threading.Lock()

    def _load(self):
        index, errors = {}, []
        for label, folder in self.dirs:
            try:
                names = sorted(n for n in os.listdir(folder) if n.endswith(".xml"))
            except OSError as e:
                errors.append(f"{folder}: {e.strerror}")
                continue
            for name in names:
                try:
                    text = open(os.path.join(folder, name), encoding="utf-8", errors="replace").read()
                except OSError as e:
                    errors.append(f"{name}: {e.strerror}")
                    continue
                for m in RULE_BLOCK.finditer(text):
                    col = m.start() - text.rfind("\n", 0, m.start()) - 1
                    lines = m.group(0).split("\n")
                    xml = "\n".join([lines[0]] + [l[min(col, len(l) - len(l.lstrip(" "))):] for l in lines[1:]])
                    index.setdefault(m.group(1), []).append({"file": f"{label}/{name}", "xml": xml[:20000]})
        self.index, self.loaded = index, time.time()
        self.error = ("Cannot read the Wazuh rule files: " + "; ".join(errors[:2])) if errors and not index else None

    def get(self, rule_id):
        with self.lock:
            if time.time() - self.loaded > 300:
                self._load()
            return self.index.get(rule_id, [])

    def count(self):
        with self.lock:
            if not self.loaded:
                self._load()
            return len(self.index)


# ----------------------------------------------------------------------------------------------- triage notes
class Triage:
    STATUSES = ("new", "investigating", "true_positive", "false_positive", "benign")
    ID_RE = re.compile(r"^[\w.:-]{1,80}$")

    def __init__(self):
        self.lock = threading.Lock()
        self.where = "disk"
        try:
            os.makedirs(STATE_DIR, exist_ok=True)
            self.db = sqlite3.connect(os.path.join(STATE_DIR, "triage.db"), check_same_thread=False)
            self.db.execute("PRAGMA journal_mode=WAL")
        except (OSError, sqlite3.Error):
            self.db = sqlite3.connect(":memory:", check_same_thread=False)
            self.where = "memory"
        with self.lock:
            self.db.executescript("""
                CREATE TABLE IF NOT EXISTS triage (alert_id TEXT PRIMARY KEY, status TEXT NOT NULL, note TEXT NOT NULL DEFAULT '',
                    rule_id TEXT, level INTEGER, agent TEXT, description TEXT, alert_time TEXT, updated_at REAL NOT NULL, updated_by TEXT);
                CREATE TABLE IF NOT EXISTS triage_log (seq INTEGER PRIMARY KEY AUTOINCREMENT, alert_id TEXT NOT NULL,
                    status TEXT NOT NULL, note TEXT NOT NULL DEFAULT '', at REAL NOT NULL, by TEXT);
                CREATE INDEX IF NOT EXISTS triage_log_alert ON triage_log(alert_id);""")
            self.db.commit()

    @staticmethod
    def _row(r):
        return {"id": r[0], "status": r[1], "note": r[2], "rule": r[3], "level": r[4], "agent": r[5],
                "description": r[6], "alert_time": r[7], "at": r[8], "by": r[9]}

    def get_many(self, ids):
        ids = [i for i in ids if isinstance(i, str) and self.ID_RE.match(i)][:1000]
        out = {}
        with self.lock:
            for start in range(0, len(ids), 400):
                chunk = ids[start:start + 400]
                rows = self.db.execute(f"SELECT * FROM triage WHERE alert_id IN ({','.join('?' * len(chunk))})", chunk)
                for r in rows:
                    out[r[0]] = self._row(r)
        return out

    def set(self, body, user):
        alert_id = str(body.get("id", ""))
        status = str(body.get("status", ""))
        note = str(body.get("note", ""))[:2000]
        if not self.ID_RE.match(alert_id):
            raise Problem(400, "Unknown alert id.")
        if status not in self.STATUSES:
            raise Problem(400, "Unknown triage status.")
        level = body.get("level")
        level = int(level) if isinstance(level, (int, float)) or (isinstance(level, str) and level.isdigit()) else None
        row = (alert_id, status, note, str(body.get("rule", ""))[:12], level, str(body.get("agent", ""))[:120],
               str(body.get("description", ""))[:400], str(body.get("alert_time", ""))[:40], time.time(), user)
        with self.lock:
            self.db.execute("INSERT OR REPLACE INTO triage VALUES (?,?,?,?,?,?,?,?,?,?)", row)
            self.db.execute("INSERT INTO triage_log (alert_id, status, note, at, by) VALUES (?,?,?,?,?)",
                            (alert_id, status, note, row[8], user))
            self.db.commit()
        return self._row(row)

    def history(self, alert_id):
        with self.lock:
            rows = self.db.execute("SELECT status, note, at, by FROM triage_log WHERE alert_id=? ORDER BY seq DESC LIMIT 50",
                                   (alert_id,)).fetchall()
        return [{"status": r[0], "note": r[1], "at": r[2], "by": r[3]} for r in rows]

    def ids_with(self, statuses, limit=50000):
        """Alert ids whose current triage status is one of these (for the Alerts page's triage filter)."""
        statuses = [x for x in statuses if x in self.STATUSES]
        if not statuses:
            return []
        with self.lock:
            rows = self.db.execute(f"SELECT alert_id FROM triage WHERE status IN ({','.join('?' * len(statuses))}) "
                                   "ORDER BY updated_at DESC LIMIT ?", (*statuses, limit)).fetchall()
        return [r[0] for r in rows]

    def summary(self):
        with self.lock:
            rows = self.db.execute("SELECT status, COUNT(*) FROM triage GROUP BY status").fetchall()
        return {r[0]: r[1] for r in rows}

    def recent(self, limit=40):
        with self.lock:
            rows = self.db.execute("SELECT * FROM triage ORDER BY updated_at DESC LIMIT ?", (limit,)).fetchall()
        return [self._row(r) for r in rows]


# ----------------------------------------------------------------------------------------------- live alert file
class AlertStore:
    """Follows alerts.json (surviving Wazuh's daily rotation) and keeps the library's alerts for the live board."""

    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()
        self.alerts = collections.deque(maxlen=KEEP)
        self.seq = 0
        self.agents = {}          # agent name -> {"id", "ip", "last": timestamp of its latest alert of any kind}
        self.lines = 0
        self.bad_lines = 0
        self.status = "starting"

    def ingest(self, line):
        self.lines += 1
        try:
            alert = json.loads(line)
        except ValueError:
            self.bad_lines += 1
            return
        agent = alert.get("agent") or {}
        name = agent.get("name")
        if name:
            with self.lock:
                self.agents[name] = {"id": agent.get("id"), "ip": agent.get("ip"), "last": alert.get("timestamp")}
        rid = str((alert.get("rule") or {}).get("id", ""))
        if rid not in RULE_UC:
            return
        with self.lock:
            self.seq += 1
            self.alerts.append({"seq": self.seq, "uc": RULE_UC[rid], "alert": clip(alert)})

    def follow(self):
        handle, inode, pending = None, None, ""
        while True:
            try:
                if handle is None:
                    handle = open(self.path, "r", encoding="utf-8", errors="replace")
                    inode = os.fstat(handle.fileno()).st_ino
                    self.status = "following"
                chunk = handle.readline()
                if chunk:
                    pending += chunk
                    if pending.endswith("\n"):
                        self.ingest(pending.strip())
                        pending = ""
                    continue
                time.sleep(0.5)
                st = os.stat(self.path)
                if st.st_ino != inode or st.st_size < handle.tell():   # rotated or truncated: start the new file
                    handle.close()
                    handle, pending = None, ""
            except FileNotFoundError:
                self.status = f"waiting for {self.path}"
                handle = None
                time.sleep(2)
            except PermissionError:
                self.status = f"no permission to read {self.path}"
                handle = None
                time.sleep(5)

    def since(self, after, limit=1500):
        with self.lock:
            items = [a for a in self.alerts if a["seq"] > after]
            return items[-limit:], self.seq, dict(self.agents)


STORE = AlertStore(ALERTS)
INDEXER = API = RULES = TRIAGE = None


def init_services():
    """Created at start-up, not at import, so `--hash-password` (run by root in the installer) touches nothing."""
    global INDEXER, API, RULES, TRIAGE
    INDEXER, API, RULES, TRIAGE = Indexer(), WazuhApi(), RuleBook(), Triage()


# ----------------------------------------------------------------------------------------------- query building
def window(q):
    now = time.time()
    rng = one(q, "range", "24h")
    if rng == "custom":
        try:
            start = int(one(q, "from")) / 1000
            end = int(one(q, "to") or now * 1000) / 1000
        except ValueError:
            raise Problem(400, "Choose a valid start and end time.")
    else:
        start, end = now - RANGES.get(rng, 86400), now
    if not 0 < start < end:
        raise Problem(400, "The start of the time range must be before its end.")
    if end - start > 400 * 86400:
        raise Problem(400, "Choose a time range of at most 400 days.")
    interval = next((name for name, secs in INTERVALS if (end - start) / secs <= 72), "1d")
    return int(start * 1000), int(end * 1000), interval


def time_filter(start, end):
    return {"range": {"timestamp": {"gte": start, "lte": end, "format": "epoch_millis"}}}


def hist_agg(start, end, interval, levels=True):
    agg = {"date_histogram": {"field": "timestamp", "fixed_interval": interval, "min_doc_count": 0,
                              "extended_bounds": {"min": start, "max": end}}}
    if levels:
        agg["aggs"] = {"lv": {"range": {"field": "rule.level", "ranges": SEVERITY}}}
    return agg


def read_hist(agg):
    out = []
    for b in (agg or {}).get("buckets", []):
        row = {"t": b.get("key"), "n": b.get("doc_count", 0)}
        for r in (b.get("lv") or {}).get("buckets", []):
            row[r.get("key")] = r.get("doc_count", 0)
        out.append(row)
    return out


def read_levels(agg):
    return {b.get("key"): b.get("doc_count", 0) for b in (agg or {}).get("buckets", [])}


def looks_like_lucene(text):
    return bool(FIELD_SYNTAX.search(text) or LUCENE_HINT.search(text))


def contains_query(text):
    """Every word must appear somewhere: inside one of the common fields (case-insensitive) or in the original log.
    * and ? typed by the user stay wildcards. Wazuh stores Windows paths with doubled backslashes, so a word with
    a backslash is also tried in that form (C:\\Users finds C:\\\\Users)."""
    must = []
    for word in [w for w in re.split(r"\s+", text.strip()) if w][:8]:
        word = word[:200]
        forms = {word}
        if "\\" in word:
            forms.add(re.sub(r"\\+", lambda m: "\\\\", word))
        should = [{"match_phrase": {"full_log": word.replace("*", " ").replace("?", " ")}}]
        for form in sorted(forms):
            pattern = "*" + form.replace("\\", "\\\\") + "*"
            should += [{"wildcard": {f: {"value": pattern, "case_insensitive": True}}} for f in CONTAINS_FIELDS]
        must.append({"bool": {"should": should, "minimum_should_match": 1}})
    return {"bool": {"must": must}}


def field_value(spec):
    field, sep, value = spec.partition(":")
    if not sep or not FIELD_RE.match(field):
        raise Problem(400, "A filter must look like field:value.")
    return field, value[:1000]


def build_filters(q, start, end):
    flt, neg = [time_filter(start, end)], []
    if one(q, "ours") == "1":
        flt.append({"terms": {"rule.id": OUR_RULES}})
    uc = one(q, "uc")
    if uc:
        ids = UC_RULES.get(as_int(uc, 0, 0, 99, "Use case"))
        if not ids:
            raise Problem(400, "Unknown use case.")
        flt.append({"terms": {"rule.id": ids}})
    level = one(q, "level")
    if level:
        flt.append({"range": {"rule.level": {"gte": as_int(level, 0, 0, 16, "Level")}}})
    for key, field in (("agent", "agent.name"), ("agent_id", "agent.id"), ("rule", "rule.id"), ("tactic", "rule.mitre.tactic"),
                       ("technique", "rule.mitre.id"), ("group", "rule.groups"), ("decoder", "decoder.name"),
                       ("location", "location")):
        value = one(q, key)
        if value:
            flt.append({"term": {field: value[:300]}})
    triage = one(q, "triage")
    if triage:
        # triage lives in the console's own database, so it becomes a list of alert ids for the indexer
        if triage == "waiting":            # never triaged, or set back to New
            done = TRIAGE.ids_with([x for x in Triage.STATUSES if x != "new"])
            if done:
                neg.append({"terms": {"id": done}})
        elif triage in TRIAGE_GROUPS:
            flt.append({"terms": {"id": TRIAGE.ids_with(TRIAGE_GROUPS[triage])}})
        else:
            raise Problem(400, "Unknown triage filter.")
    for spec in q.get("f", [])[:20]:
        field, value = field_value(spec)
        flt.append({"term": {field: value}})
    for spec in q.get("nf", [])[:20]:
        field, value = field_value(spec)
        neg.append({"term": {field: value}})
    return flt, neg


TRIAGE_GROUPS = {"investigating": ["investigating"], "closed": ["true_positive", "false_positive", "benign"],
                 "true_positive": ["true_positive"], "false_positive": ["false_positive"], "benign": ["benign"]}


def lucene_operators(text):
    """The Wazuh dashboard's query language accepts and / or / not in any case; Lucene only in capitals. Upper-case
    them outside quoted phrases, so a search copied from Threat Hunting (rule.id:1 or rule.id:2) works the same here."""
    out = []
    for i, part in enumerate(re.split(r'("(?:[^"\\]|\\.)*")', text)):
        if i % 2 == 0:
            part = re.sub(r"(?i)(?<![\w.:-])(and|or|not)(?=\s|\(|$)", lambda m: m.group(1).upper(), part)
        out.append(part)
    return "".join(out)


def text_clause(text, mode):
    if mode == "lucene":
        return [{"query_string": {"query": lucene_operators(text), "analyze_wildcard": True, "allow_leading_wildcard": True,
                                  "default_operator": "AND", "lenient": True}}]
    if mode == "contains":
        return [contains_query(text)]
    return []


def facet_aggs(kind):
    aggs = {}
    for i, (field, size) in enumerate(FACETS[kind]):
        agg = {"terms": {"field": field, "size": size}}
        if field == "rule.id":
            agg["aggs"] = {"d": {"terms": {"field": "rule.description", "size": 1}}, "lv": {"max": {"field": "rule.level"}}}
        aggs[f"f{i}"] = agg
    return aggs


def read_facets(kind, aggs):
    out = {}
    for i, (field, _) in enumerate(FACETS[kind]):
        rows = []
        for b in (aggs.get(f"f{i}") or {}).get("buckets", []):
            row = {"value": str(b.get("key")), "n": b.get("doc_count", 0)}
            if field == "rule.id":
                desc = (b.get("d") or {}).get("buckets") or []
                row.update(label=desc[0]["key"] if desc else "", level=(b.get("lv") or {}).get("value"),
                           uc=uc_of(b.get("key")))
            rows.append(row)
        out[field] = rows
    return out


def total_of(hits):
    total = hits.get("total", 0)
    if isinstance(total, dict):
        return total.get("value", 0), total.get("relation", "eq")
    return total, "eq"


def search_with_fallback(kind, text, make_body):
    """Lucene syntax when the text looks like a query; if OpenSearch cannot parse it, search it as plain words."""
    mode = ("lucene" if looks_like_lucene(text) else "contains") if text else "none"
    try:
        return INDEXER.search(kind, make_body(mode)), mode, None
    except Problem as p:
        if p.status != 400 or mode != "lucene":
            raise
        res = INDEXER.search(kind, make_body("contains"))
        return res, "contains", f"Searched as plain words, because the query syntax was not valid: {p.message[:180]}"


# ----------------------------------------------------------------------------------------------- endpoints
def api_search(q):
    kind = one(q, "kind", "alerts")
    if kind not in INDEX:
        raise Problem(400, "Unknown search kind.")
    start, end, interval = window(q)
    flt, neg = build_filters(q, start, end)
    text = one(q, "q").strip()[:2000]
    size = as_int(one(q, "size"), 50, 1, 200, "Page size")
    page = as_int(one(q, "page"), 0, 0, MAX_WINDOW, "Page")
    if (page + 1) * size > MAX_WINDOW:
        raise Problem(400, "Only the first 10,000 results can be paged. Narrow the search or the time range.")
    order = "asc" if one(q, "sort") == "asc" else "desc"

    def body(mode):
        return {"size": size, "from": page * size, "sort": [{"timestamp": {"order": order}}],
                "track_total_hits": True, "timeout": "20s",
                "query": {"bool": {"filter": flt + text_clause(text, mode), "must_not": neg}},
                "aggs": {"hist": hist_agg(start, end, interval, levels=kind == "alerts"), **facet_aggs(kind)}}

    res, mode, note = search_with_fallback(kind, text, body)
    hits = res.get("hits") or {}
    total, relation = total_of(hits)
    aggs = res.get("aggregations") or {}
    items = []
    for h in hits.get("hits", []):
        src = h.get("_source") or {}
        items.append({"_id": h.get("_id"), "_index": h.get("_index"), "uc": uc_of(dig(src, "rule.id")), "doc": clip(src)})
    return {"kind": kind, "mode": mode, "note": note, "total": total, "relation": relation, "took": res.get("took"),
            "timed_out": res.get("timed_out", False), "from": start, "to": end, "interval": interval,
            "index_missing": (res.get("_shards") or {}).get("total", 1) == 0, "page": page, "size": size,
            "histogram": read_hist(aggs.get("hist")), "facets": read_facets(kind, aggs), "hits": items}


def csv_safe(value):
    if isinstance(value, list):
        value = " ".join(str(v) for v in value)
    text = "" if value is None else str(value)
    text = text.replace("\r", " ").replace("\n", " ")[:2000]
    # cells that start like a formula are opened as text by spreadsheet programs (CSV injection)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t") else text


def api_export(q):
    kind = one(q, "kind", "alerts")
    if kind not in INDEX:
        raise Problem(400, "Unknown search kind.")
    start, end, _ = window(q)
    flt, neg = build_filters(q, start, end)
    text = one(q, "q").strip()[:2000]
    limit = as_int(one(q, "limit"), 2000, 1, 5000, "Limit")
    columns = EXPORT_COLUMNS[kind]

    def body(mode):
        return {"size": limit, "sort": [{"timestamp": {"order": "desc"}}], "timeout": "30s", "_source": {"includes": columns},
                "query": {"bool": {"filter": flt + text_clause(text, mode), "must_not": neg}}}

    res, _, _ = search_with_fallback(kind, text, body)
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(columns)
    for h in (res.get("hits") or {}).get("hits", []):
        src = h.get("_source") or {}
        writer.writerow([csv_safe(dig(src, c)) for c in columns])
    stamp = time.strftime("%Y%m%d-%H%M", time.localtime())
    return out.getvalue().encode("utf-8-sig"), f"moe-{kind}-{stamp}.csv"


_health_cache = {"at": 0.0, "data": None}
_health_lock = threading.Lock()


def system_health(force=False):
    """Indexer, server API, agents and pipeline in one place; cached for 20 seconds."""
    with _health_lock:
        if not force and _health_cache["data"] and time.time() - _health_cache["at"] < 20:
            return _health_cache["data"]
    h = {"alerts_file": STORE.status, "indexer": {"configured": INDEXER.up is not None}, "api": {"configured": API.up is not None}}
    if INDEXER.up:
        ix = h["indexer"]
        try:
            info = INDEXER.call("GET", "/")
            ix["version"] = dig(info, "version.number")
            ix["ok"] = True
            try:
                ix["cluster"] = INDEXER.call("GET", "/_cluster/health").get("status")
            except Problem:
                ix["cluster"] = None
            latest = INDEXER.search("alerts", {"size": 1, "_source": ["timestamp"], "sort": [{"timestamp": {"order": "desc"}}],
                                               "query": {"range": {"timestamp": {"gte": "now-30d"}}}})
            top = (latest.get("hits") or {}).get("hits") or []
            ix["latest_alert"] = dig(top[0].get("_source") or {}, "timestamp") if top else None
            arch = INDEXER.search("logs", {"size": 0, "track_total_hits": True,
                                           "query": {"range": {"timestamp": {"gte": "now-24h"}}}})
            ix["archives"] = (arch.get("_shards") or {}).get("total", 0) > 0
            ix["archives_24h"] = total_of(arch.get("hits") or {})[0]
            vul = INDEXER.search(VULN_INDEX, {"size": 0})
            ix["vulnerabilities"] = (vul.get("_shards") or {}).get("total", 0) > 0
        except Problem as p:
            ix.update(ok=False, error=p.message)
    else:
        h["indexer"]["error"] = INDEXER.error
    if API.up:
        api = h["api"]
        try:
            info = (API.get("/manager/info", ttl=60).get("affected_items") or [{}])[0]
            api.update(ok=True, version=info.get("version"), tz=info.get("tz_name"))
            daemons = (API.get("/manager/status", ttl=20).get("affected_items") or [{}])[0]
            api["stopped"] = [d for d in KEY_DAEMONS if d in daemons and daemons[d] != "running"]
            summary = API.get("/agents/summary/status", ttl=10)
            api["agents"] = summary.get("connection", summary)
        except Problem as p:
            api.update(ok=False, error=p.message)
    else:
        h["api"]["error"] = API.error
    with _health_lock:
        _health_cache.update(at=time.time(), data=h)
    return h


def api_status(q):
    return {"version": VERSION, "demo": DEMO, "user": None if AUTH_OFF else Handler.user, "login": not AUTH_OFF, "triage": TRIAGE.where, "rules": {"count": RULES.count(), "error": RULES.error},
            "health": system_health(force=one(q, "fresh") == "1"), "catalogue": {"usecases": len(CATALOGUE["usecases"]),
                                                                                  "rules": len(OUR_RULES)}}


def uc_stats_from(buckets):
    stats = {}
    for b in buckets:
        n = uc_of(b.get("key"))
        if n is None:
            continue
        s = stats.setdefault(n, {"n": n, "hits": 0, "level": 0, "last": 0, "rules": {}})
        s["hits"] += b.get("doc_count", 0)
        s["level"] = max(s["level"], int((b.get("lv") or {}).get("value") or 0))
        s["last"] = max(s["last"], int((b.get("last") or {}).get("value") or 0))
        s["rules"][str(b.get("key"))] = b.get("doc_count", 0)
    return stats


def top_rules(agg):
    rows = []
    for b in (agg or {}).get("buckets", []):
        desc = (b.get("d") or {}).get("buckets") or []
        rows.append({"id": str(b.get("key")), "n": b.get("doc_count", 0), "label": desc[0]["key"] if desc else "",
                     "level": int((b.get("lv") or {}).get("value") or 0), "uc": uc_of(b.get("key"))})
    return rows


def hit_list(agg):
    out = []
    for h in ((agg or {}).get("hits") or {}).get("hits", []):
        src = h.get("_source") or {}
        out.append({"_id": h.get("_id"), "uc": uc_of(dig(src, "rule.id")), "doc": clip(src)})
    return out


def rule_aggs():
    return {"terms": {"field": "rule.id", "size": 10},
            "aggs": {"d": {"terms": {"field": "rule.description", "size": 1}}, "lv": {"max": {"field": "rule.level"}}}}


def ours_aggs(start=None, end=None, interval=None):
    agg = {"filter": {"terms": {"rule.id": OUR_RULES}},
           "aggs": {"rules": {"terms": {"field": "rule.id", "size": 250},
                              "aggs": {"lv": {"max": {"field": "rule.level"}}, "last": {"max": {"field": "timestamp"}}}}}}
    if interval:
        agg["aggs"]["hist"] = hist_agg(start, end, interval, levels=False)
    return agg


def api_overview(q):
    start, end, interval = window(q)
    rng = time_filter(start, end)
    body = {"size": 0, "track_total_hits": True, "timeout": "20s", "query": {"bool": {"filter": [rng]}},
            "aggs": {"hist": hist_agg(start, end, interval),
                     "levels": {"range": {"field": "rule.level", "ranges": SEVERITY}},
                     "agents": {"terms": {"field": "agent.name", "size": 8}, "aggs": {"lv": {"max": {"field": "rule.level"}}}},
                     "rules": rule_aggs(),
                     "tactics": {"terms": {"field": "rule.mitre.tactic", "size": 20}},
                     "ours": ours_aggs(start, end, interval),
                     "high": {"filter": {"range": {"rule.level": {"gte": 12}}},
                              "aggs": {"latest": {"top_hits": {"size": 8, "sort": [{"timestamp": {"order": "desc"}}],
                                                               "_source": {"includes": SUMMARY_FIELDS}}}}}}}
    res = INDEXER.search("alerts", body)
    aggs = res.get("aggregations") or {}
    ours = aggs.get("ours") or {}
    # triage state of the newest high-severity alerts in the window
    ids_res = INDEXER.search("alerts", {"size": 500, "_source": ["id"], "sort": [{"timestamp": {"order": "desc"}}],
                                        "query": {"bool": {"filter": [rng, {"range": {"rule.level": {"gte": 12}}}]}}})
    ids = [dig(h.get("_source") or {}, "id") for h in (ids_res.get("hits") or {}).get("hits", [])]
    ids = [i for i in ids if i]
    states = TRIAGE.get_many(ids)
    counts = collections.Counter((states.get(i) or {}).get("status", "new") for i in ids)
    return {"from": start, "to": end, "interval": interval, "total": total_of(res.get("hits") or {})[0],
            "histogram": read_hist(aggs.get("hist")), "levels": read_levels(aggs.get("levels")),
            "agents": [{"name": b.get("key"), "n": b.get("doc_count", 0), "level": int((b.get("lv") or {}).get("value") or 0)}
                       for b in (aggs.get("agents") or {}).get("buckets", [])],
            "rules": top_rules(aggs.get("rules")),
            "tactics": [{"name": b.get("key"), "n": b.get("doc_count", 0)} for b in (aggs.get("tactics") or {}).get("buckets", [])],
            "ours": {"total": ours.get("doc_count", 0), "histogram": read_hist(ours.get("hist")),
                     "usecases": list(uc_stats_from((ours.get("rules") or {}).get("buckets", [])).values())},
            "latest_high": hit_list((aggs.get("high") or {}).get("latest")),
            "triage": {"high_in_window": len(ids), "untriaged": counts.get("new", 0), "investigating": counts.get("investigating", 0),
                       "closed": len(ids) - counts.get("new", 0) - counts.get("investigating", 0), "all": TRIAGE.summary()},
            "health": system_health()}


def api_usecase_stats(q):
    start, end, _ = window(q)
    res = INDEXER.search("alerts", {"size": 0, "timeout": "20s", "query": {"bool": {"filter": [time_filter(start, end)]}},
                                    "aggs": {"ours": ours_aggs()}})
    ours = (res.get("aggregations") or {}).get("ours") or {}
    return {"from": start, "to": end, "total": ours.get("doc_count", 0),
            "usecases": list(uc_stats_from((ours.get("rules") or {}).get("buckets", [])).values())}


def api_attack(q):
    start, end, _ = window(q)
    body = {"size": 0, "timeout": "20s", "query": {"bool": {"filter": [time_filter(start, end)]}},
            "aggs": {"all": {"terms": {"field": "rule.mitre.id", "size": 600},
                             "aggs": {"one": {"top_hits": {"size": 1, "_source": {"includes": ["rule.mitre"]}}}}},
                     "ours": {"filter": {"terms": {"rule.id": OUR_RULES}},
                              "aggs": {"t": {"terms": {"field": "rule.mitre.id", "size": 300}}}}}}
    res = INDEXER.search("alerts", body)
    aggs = res.get("aggregations") or {}
    techniques = {}
    for b in (aggs.get("all") or {}).get("buckets", []):
        tid = str(b.get("key"))
        known = CATALOGUE["techniques"].get(tid)
        name, tactics = (known["name"], known["tactics"]) if known else ("", [])
        if not known:
            hits = ((b.get("one") or {}).get("hits") or {}).get("hits") or []
            mitre = dig(hits[0].get("_source") or {}, "rule.mitre", {}) if hits else {}
            ids = mitre.get("id") or []
            names = mitre.get("technique") or []
            if tid in ids and ids.index(tid) < len(names):
                name = names[ids.index(tid)]
            tactics = mitre.get("tactic") or []
        techniques[tid] = {"all": b.get("doc_count", 0), "ours": 0, "name": name, "tactics": tactics}
    for b in ((aggs.get("ours") or {}).get("t") or {}).get("buckets", []):
        tid = str(b.get("key"))
        techniques.setdefault(tid, {"all": b.get("doc_count", 0), "name": "", "tactics": []})["ours"] = b.get("doc_count", 0)
    return {"from": start, "to": end, "techniques": techniques}


AGENT_FIELDS = "id,name,ip,status,os.name,os.version,os.platform,version,lastKeepAlive,dateAdd,group,node_name,registerIP"


def api_agents(q):
    start, end, _ = window(q)
    out = {"source": "api", "summary": None, "agents": [], "stats": {}, "notes": []}
    try:
        data = API.get("/agents", {"limit": 1000, "sort": "+id", "select": AGENT_FIELDS}, ttl=10)
        out["agents"] = data.get("affected_items") or []
        summary = API.get("/agents/summary/status", ttl=10)
        out["summary"] = summary.get("connection", summary)
    except Problem as p:
        out["source"] = "alerts"
        out["notes"].append(p.message)
        with STORE.lock:
            seen = dict(STORE.agents)
        out["agents"] = [{"id": v.get("id"), "name": k, "ip": v.get("ip"), "status": None, "lastSeen": v.get("last")}
                         for k, v in sorted(seen.items(), key=lambda kv: str(kv[1].get("id")))]
    try:
        res = INDEXER.search("alerts", {"size": 0, "timeout": "20s", "query": {"bool": {"filter": [time_filter(start, end)]}},
                                        "aggs": {"a": {"terms": {"field": "agent.id", "size": 500},
                                                       "aggs": {"lv": {"max": {"field": "rule.level"}},
                                                                "last": {"max": {"field": "timestamp"}},
                                                                "ours": {"filter": {"terms": {"rule.id": OUR_RULES}}},
                                                                "high": {"filter": {"range": {"rule.level": {"gte": 12}}}},
                                                                "name": {"terms": {"field": "agent.name", "size": 1}}}}}})
        for b in ((res.get("aggregations") or {}).get("a") or {}).get("buckets", []):
            names = (b.get("name") or {}).get("buckets") or []
            out["stats"][str(b.get("key"))] = {
                "alerts": b.get("doc_count", 0), "level": int((b.get("lv") or {}).get("value") or 0),
                "last": int((b.get("last") or {}).get("value") or 0), "ours": (b.get("ours") or {}).get("doc_count", 0),
                "high": (b.get("high") or {}).get("doc_count", 0), "name": names[0]["key"] if names else ""}
        if out["source"] == "alerts":
            known = {str(a.get("id")) for a in out["agents"]}
            for aid, s in out["stats"].items():
                if aid not in known:
                    out["agents"].append({"id": aid, "name": s["name"], "status": None})
    except Problem as p:
        out["notes"].append(p.message)
    return out


def api_agent(q):
    aid = one(q, "id")
    if not AGENT_ID.match(aid):
        raise Problem(400, "Unknown agent id.")
    start, end, interval = window(q)
    out = {"id": aid, "agent": None, "sca": None, "os": None, "hardware": None, "notes": [], "vulnerabilities": None}
    try:
        items = API.get("/agents", {"agents_list": aid}, ttl=10).get("affected_items") or []
        out["agent"] = items[0] if items else None
        out["sca"] = API.get(f"/sca/{aid}", ttl=60).get("affected_items") or []
        for part in ("os", "hardware"):
            try:
                out[part] = (API.get(f"/syscollector/{aid}/{part}", ttl=120).get("affected_items") or [None])[0]
            except Problem:
                pass
    except Problem as p:
        out["notes"].append(p.message)
    rng = time_filter(start, end)
    who = {"term": {"agent.id": aid}}
    try:
        res = INDEXER.search("alerts", {
            "size": 0, "track_total_hits": True, "timeout": "20s", "query": {"bool": {"filter": [rng, who]}},
            "aggs": {"hist": hist_agg(start, end, interval), "levels": {"range": {"field": "rule.level", "ranges": SEVERITY}},
                     "rules": rule_aggs(), "ours": ours_aggs(),
                     "fim": {"filter": {"term": {"rule.groups": "syscheck"}},
                             "aggs": {"latest": {"top_hits": {"size": 10, "sort": [{"timestamp": {"order": "desc"}}],
                                                              "_source": {"includes": SUMMARY_FIELDS + ["syscheck"]}}}}},
                     "latest": {"top_hits": {"size": 10, "sort": [{"timestamp": {"order": "desc"}}],
                                             "_source": {"includes": SUMMARY_FIELDS}}}}})
        aggs = res.get("aggregations") or {}
        out.update(total=total_of(res.get("hits") or {})[0], histogram=read_hist(aggs.get("hist")),
                   levels=read_levels(aggs.get("levels")), rules=top_rules(aggs.get("rules")),
                   usecases=list(uc_stats_from(((aggs.get("ours") or {}).get("rules") or {}).get("buckets", [])).values()),
                   fim=hit_list((aggs.get("fim") or {}).get("latest")), latest=hit_list(aggs.get("latest")),
                   **{"from": start, "to": end, "interval": interval})
    except Problem as p:
        out["notes"].append(p.message)
    try:
        vul = INDEXER.search(VULN_INDEX, {
            "size": 8, "track_total_hits": True, "query": {"term": {"agent.id": aid}},
            "sort": [{"vulnerability.score.base": {"order": "desc", "unmapped_type": "float"}}],
            "_source": {"includes": ["vulnerability.id", "vulnerability.severity", "vulnerability.score.base",
                                     "package.name", "package.version"]},
            "aggs": {"sev": {"terms": {"field": "vulnerability.severity", "size": 10}}}})
        if (vul.get("_shards") or {}).get("total", 0) > 0:
            out["vulnerabilities"] = {
                "total": total_of(vul.get("hits") or {})[0],
                "severity": {b.get("key"): b.get("doc_count", 0) for b in ((vul.get("aggregations") or {}).get("sev") or {}).get("buckets", [])},
                "top": [h.get("_source") or {} for h in (vul.get("hits") or {}).get("hits", [])]}
    except Problem:
        pass
    return out


def api_rule(q):
    rid = one(q, "id")
    if not re.fullmatch(r"\d{1,7}", rid):
        raise Problem(400, "A rule id is a number.")
    entries, source = RULES.get(rid), "server"
    if not entries and rid in CATALOGUE["rule_xml"]:
        entry = CATALOGUE["rule_xml"][rid]
        entries, source = [{"file": "library/" + entry["file"], "xml": entry["xml"]}], "library"
    if not entries:
        source = None
    xml = entries[0]["xml"] if entries else ""

    def ids(tag):
        out = []
        for block in re.findall(rf"<{tag}>([^<]+)</{tag}>", xml):
            out += [p for p in re.split(r"[\s,]+", block) if p.isdigit()]
        return list(dict.fromkeys(out))

    def names(tag):
        return [g.strip() for g in re.findall(rf"<{tag}>([^<]+)</{tag}>", xml)]

    lists = re.findall(r"<list[^>]*>([^<]+)</list>", xml)
    # if_sid / if_group: checked only when that rule or group matched the SAME event (a parent).
    # if_matched_sid / if_matched_group: looks back for EARLIER events within the timeframe (a correlation).
    return {"id": rid, "source": source, "entries": entries, "uc": uc_of(rid), "parents": ids("if_sid"),
            "groups": names("if_group"), "matched": ids("if_matched_sid"), "matched_groups": names("if_matched_group"),
            "lists": lists, "error": None if entries else (RULES.error or "Rule not found in the rule files.")}


def api_triage_get(q):
    ids = [i for i in one(q, "ids").split(",") if i][:1000]
    return {"items": TRIAGE.get_many(ids)}


def api_triage_history(q):
    alert_id = one(q, "id")
    if not Triage.ID_RE.match(alert_id):
        raise Problem(400, "Unknown alert id.")
    return {"id": alert_id, "history": TRIAGE.history(alert_id)}


def api_triage_recent(q):
    return {"items": TRIAGE.recent(as_int(one(q, "limit"), 40, 1, 200, "Limit")), "summary": TRIAGE.summary()}


def api_alerts(q):
    after = as_int(one(q, "after"), 0, 0, 10 ** 12, "after")
    items, last, agents = STORE.since(after)
    return {"seq": last, "alerts": items, "agents": agents, "status": STORE.status, "lines": STORE.lines, "now": time.time()}


GET_ROUTES = {"/api/alerts": api_alerts, "/api/status": api_status, "/api/search": api_search, "/api/overview": api_overview,
              "/api/attack": api_attack, "/api/usecases": api_usecase_stats, "/api/agents": api_agents, "/api/agent": api_agent, "/api/rule": api_rule,
              "/api/triage": api_triage_get, "/api/triage/history": api_triage_history,
              "/api/triage/recent": api_triage_recent}
STATIC_NAME = re.compile(r"^(?:(?:fonts|js)/)?[A-Za-z0-9_][A-Za-z0-9_.-]*$")


# ----------------------------------------------------------------------------------------------- HTTP
class Handler(BaseHTTPRequestHandler):
    server_version = "MOE"
    sys_version = ""
    timeout = 30
    user = os.environ.get("MOE_USER", "moe")
    pass_hash = os.environ.get("MOE_PASS_HASH", "")
    sessions = {}        # sha256(Authorization header) -> expiry, so PBKDF2 runs once per login, not per poll
    sessions_lock = threading.Lock()

    def log_message(self, fmt, *args):     # access log without credentials or query strings
        sys.stderr.write("%s %s %s\n" % (self.address_string(), self.command, urlparse(self.path).path))

    def send(self, code, body, ctype, extra=None):
        data = body if isinstance(body, bytes) else body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        if isinstance(self.connection, ssl.SSLSocket):
            self.send_header("Strict-Transport-Security", "max-age=31536000")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def send_json(self, obj, code=200):
        self.send(code, json.dumps(obj, default=str), "application/json")

    def authorised(self):
        if AUTH_OFF:                 # chosen with install-console.sh --no-login
            return True
        header = self.headers.get("Authorization", "")
        if not header.startswith("Basic ") or not self.pass_hash:
            return False
        key = hashlib.sha256(header.encode()).hexdigest()
        now = time.time()
        with self.sessions_lock:
            if self.sessions.get(key, 0) > now:
                return True
        try:
            user, _, password = base64.b64decode(header[6:]).decode("utf-8").partition(":")
        except Exception:
            return False
        ok = hmac.compare_digest(user.encode(), self.user.encode()) and check_password(password, self.pass_hash)
        if ok:
            with self.sessions_lock:
                self.sessions[key] = now + 8 * 3600
        else:
            time.sleep(1)            # slows down password guessing
        return ok

    def ask_login(self):
        self.send(401, "Sign in to the MOE console.", "text/plain; charset=utf-8",
                  {"WWW-Authenticate": 'Basic realm="MOE SOC console", charset="UTF-8"'})

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        url = urlparse(self.path)
        if url.path == "/api/health":            # no login: used by the installer, reveals no alert data
            return self.send_json({"ok": True, "reading_alerts": STORE.status == "following"})
        if not self.authorised():
            return self.ask_login()
        if url.path.startswith("/api/"):
            q = parse_qs(url.query)
            try:
                if url.path == "/api/export":
                    data, filename = api_export(q)
                    return self.send(200, data, "text/csv; charset=utf-8",
                                     {"Content-Disposition": f'attachment; filename="{filename}"'})
                route = GET_ROUTES.get(url.path)
                if not route:
                    return self.send_json({"error": "Unknown address."}, 404)
                return self.send_json(route(q))
            except Problem as p:
                return self.send_json({"error": p.message, **p.extra}, p.status)
            except Exception:
                traceback.print_exc()
                return self.send_json({"error": "Unexpected error in the console. Details: journalctl -u moe-console"}, 500)
        name = "index.html" if url.path in ("/", "/index.html") else None
        if url.path.startswith("/static/"):
            rel = url.path[len("/static/"):]
            if STATIC_NAME.match(rel) and ".." not in rel:
                name = rel
        if name:
            full = os.path.realpath(os.path.join(STATIC, name))
            ext = os.path.splitext(full)[1]
            if full.startswith(os.path.realpath(STATIC) + os.sep) and ext in STATIC_TYPES and os.path.isfile(full):
                return self.send(200, open(full, "rb").read(), STATIC_TYPES[ext])
        return self.send(404, "Not found.", "text/plain; charset=utf-8")

    def do_POST(self):
        url = urlparse(self.path)
        if not self.authorised():
            return self.ask_login()
        if url.path != "/api/triage":
            return self.send(405, "Not allowed.", "text/plain; charset=utf-8", {"Allow": "GET, HEAD"})
        # Forgery defence: a plain cross-site form cannot set this header or a JSON content type without a CORS
        # preflight, which this server never approves; the Origin, when sent, must be this console.
        origin = self.headers.get("Origin")
        if (self.headers.get("X-MOE-Request") != "1"
                or not self.headers.get("Content-Type", "").startswith("application/json")
                or (origin and urlparse(origin).netloc != self.headers.get("Host", ""))):
            return self.send_json({"error": "Request refused."}, 403)
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = -1
        if not 0 < length <= 16384:
            return self.send_json({"error": "Request too large or empty."}, 413)
        try:
            body = json.loads(self.rfile.read(length).decode("utf-8"))
            if not isinstance(body, dict):
                raise ValueError
            return self.send_json(TRIAGE.set(body, self.user))
        except ValueError:
            return self.send_json({"error": "The request was not valid JSON."}, 400)
        except Problem as p:
            return self.send_json({"error": p.message}, p.status)
        except sqlite3.Error as e:
            traceback.print_exc()
            return self.send_json({"error": f"Could not save the triage note ({e}). Check that {STATE_DIR} belongs to moe-console."}, 500)


def main():
    if "--hash-password" in sys.argv:
        first = getpass.getpass("New console password: ")
        if len(first) < 10:
            sys.exit("Use at least 10 characters.")
        if getpass.getpass("Repeat it: ") != first:
            sys.exit("The two passwords differ.")
        print(hash_password(first))
        return
    init_services()
    if "--check" in sys.argv:            # used by the installer: can the service reach everything it needs?
        h = system_health(force=True)
        print(json.dumps({"alerts_dir": os.access(os.path.dirname(ALERTS), os.R_OK), "rules": RULES.count(),
                          "rules_error": RULES.error, "triage": TRIAGE.where, **h}, indent=1, default=str))
        bad = (h["indexer"]["configured"] and not h["indexer"].get("ok")) or (h["api"]["configured"] and not h["api"].get("ok"))
        sys.exit(1 if bad else 0)
    if not Handler.pass_hash and not AUTH_OFF:
        sys.exit("MOE_PASS_HASH is not set - run the installer, or: moe_console.py --hash-password")
    threading.Thread(target=STORE.follow, daemon=True).start()
    bind, port = os.environ.get("MOE_BIND", "0.0.0.0"), int(os.environ.get("MOE_PORT", "8443"))
    server = ThreadingHTTPServer((bind, port), Handler)
    server.daemon_threads = True
    if os.environ.get("MOE_PLAIN_HTTP") != "1":
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(os.environ["MOE_CERT"], os.environ["MOE_KEY"])
        # The TLS handshake runs on the first read, inside the request thread, so a client that connects and
        # stays silent cannot block the listener.
        server.socket = ctx.wrap_socket(server.socket, server_side=True, do_handshake_on_connect=False)
    print(f"MOE console {VERSION} on {'http' if os.environ.get('MOE_PLAIN_HTTP') == '1' else 'https'}://{bind}:{port} "
          f"following {ALERTS}; indexer {'on' if INDEXER.up else 'off'}, API {'on' if API.up else 'off'}"
          f"{'; SIGN-IN OFF: anyone who can reach this port can read everything' if AUTH_OFF else ''}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
