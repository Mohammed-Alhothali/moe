#!/usr/bin/env python3
"""Test double for the two Wazuh services the MOE console talks to.

* "Indexer" (OpenSearch subset) on https://127.0.0.1:19200, certificate signed by a test root CA:
  GET /, /_cluster/health, POST /<index pattern>/_search with the query and aggregation shapes the console uses
  (bool, range, term(s), wildcard, match_phrase, ids, exists, query_string with a small Lucene parser; date_histogram,
  terms, range, filter, max, top_hits), and the security REST API calls the installer makes.
* "Server API" on https://127.0.0.1:15500 with a self-signed certificate: authenticate, users/roles, agents, summary,
  manager info/status, SCA, syscollector.
Usage: mock_wazuh.py DATADIR CERTDIR [--no-archives]
       mock_wazuh.py DATADIR - --plain      (demo: plain HTTP on this machine only, no certificates needed)

It holds no real data and no real accounts: the passwords below are fixed demo values for this stand-in only."""
import base64, datetime, fnmatch, json, os, re, secrets, ssl, sys, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlparse

DATA, CERTS = sys.argv[1], sys.argv[2]
NO_ARCHIVES = "--no-archives" in sys.argv
STATE = {"admin_pass": os.environ.get("MOCK_ADMIN_PASS", "demo-only-1A*"), "users": {}, "roles": {}, "mappings": {},
         "requests": []}
day = datetime.datetime.now(datetime.timezone.utc).strftime("%Y.%m.%d")
INDICES = {f"wazuh-alerts-4.x-{day}": [json.loads(l) for l in open(f"{DATA}/alerts.ndjson", encoding="utf-8")],
           "wazuh-states-vulnerabilities-wazuh-server": [json.loads(l) for l in open(f"{DATA}/vulns.ndjson", encoding="utf-8")]}
if not NO_ARCHIVES:
    INDICES[f"wazuh-archives-4.x-{day}"] = [json.loads(l) for l in open(f"{DATA}/archives.ndjson", encoding="utf-8")]
for name, docs in INDICES.items():
    for i, d in enumerate(docs):
        d["__id"] = f"{name[:6]}{i:06d}"


class BadQuery(Exception):
    pass


def ts_ms(v):
    if isinstance(v, (int, float)):
        return int(v)
    s = str(v)
    m = re.match(r"^now(?:-(\d+)([smhd]))?$", s)
    if m:
        mult = {"s": 1, "m": 60, "h": 3600, "d": 86400}
        return int((time.time() - (int(m.group(1)) * mult[m.group(2)] if m.group(1) else 0)) * 1000)
    if re.fullmatch(r"\d{10,13}", s):
        return int(s)
    s = re.sub(r"([+-]\d\d)(\d\d)$", r"\1:\2", s)
    return int(datetime.datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp() * 1000)


def values(doc, path):
    cur = [doc]
    for part in path.split("."):
        nxt = []
        for c in cur:
            if isinstance(c, dict) and part in c:
                v = c[part]
                nxt.extend(v if isinstance(v, list) else [v])
        cur = nxt
    return [c for c in cur if not isinstance(c, dict)]


def wildcard_re(pattern, ci):
    out, i = "", 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "\\" and i + 1 < len(pattern):
            out += re.escape(pattern[i + 1]); i += 2; continue
        out += ".*" if ch == "*" else "." if ch == "?" else re.escape(ch)
        i += 1
    return re.compile(out, re.I | re.S if ci else re.S)


def tokens(s):
    return re.findall(r"\w+", str(s).lower())


def phrase_in(text, phrase):
    t, p = tokens(text), tokens(phrase)
    return bool(p) and any(t[i:i + len(p)] == p for i in range(len(t) - len(p) + 1))


# ------------------------------------------------------------------ tiny Lucene query_string
def lex(q):
    toks, i = [], 0
    while i < len(q):
        c = q[i]
        if c.isspace():
            i += 1
        elif c in "()":
            toks.append(c); i += 1
        elif c == '"':
            j = q.find('"', i + 1)
            if j < 0:
                raise BadQuery("Cannot parse '%s': Lexical error: unterminated quote" % q)
            toks.append(("PHRASE", q[i + 1:j])); i = j + 1
        else:
            j, buf = i, ""
            while j < len(q) and not q[j].isspace() and q[j] not in '()"':
                if q[j] == "\\" and j + 1 < len(q):
                    buf += q[j:j + 2]; j += 2; continue
                buf += q[j]; j += 1
                if buf.endswith(":") and j < len(q) and q[j] == '"':
                    break
            toks.append(("WORD", buf)); i = j
    return toks


def parse_query_string(q):
    toks = lex(q)
    pos = [0]

    def peek():
        return toks[pos[0]] if pos[0] < len(toks) else None

    def take():
        t = peek(); pos[0] += 1; return t

    def parse_or():
        left = parse_and()
        while peek() == ("WORD", "OR"):
            take(); left = ("or", left, parse_and())
        return left

    def parse_and():
        left = parse_not()
        while peek() not in (None, ")", ("WORD", "OR")):
            if peek() == ("WORD", "AND"):
                take()
            left = ("and", left, parse_not())
        return left

    def parse_not():
        if peek() == ("WORD", "NOT"):
            take(); return ("not", parse_not())
        return parse_atom()

    def parse_atom():
        t = take()
        if t is None:
            raise BadQuery("Cannot parse '%s': Encountered \"<EOF>\"" % q)
        if t == "(":
            e = parse_or()
            if take() != ")":
                raise BadQuery("Cannot parse '%s': Encountered \"<EOF>\" expecting \")\"" % q)
            return e
        if t == ")":
            raise BadQuery("Cannot parse '%s': Encountered \")\"" % q)
        kind, text = t
        if kind == "PHRASE":
            return ("any", text, True)
        m = re.match(r"^([A-Za-z0-9_.@-]+):(.*)$", text)
        if m:
            field, val = m.group(1), m.group(2)
            if val == "":
                nxt = take()
                if not nxt or nxt in ("(", ")"):
                    raise BadQuery("Cannot parse '%s': Encountered \"<EOF>\" at field %s" % (q, field))
                return ("field", field, nxt[1], nxt[0] == "PHRASE")
            return ("field", field, val, False)
        if text in ("AND", "OR"):
            raise BadQuery("Cannot parse '%s': Encountered \" <%s> \"" % (q, text))
        return ("any", text, False)

    tree = parse_or()
    if pos[0] != len(toks):
        raise BadQuery("Cannot parse '%s': Encountered \")\"" % q)
    return tree


def match_value(vals, val, phrase, field):
    if not phrase and re.match(r"^(>=|<=|>|<)(-?\d+(\.\d+)?)$", val):
        op, num = re.match(r"^(>=|<=|>|<)(.*)$", val).groups()
        num = float(num)
        for v in vals:
            try:
                f = float(v)
            except (TypeError, ValueError):
                continue
            if {">=": f >= num, "<=": f <= num, ">": f > num, "<": f < num}[op]:
                return True
        return False
    if field == "full_log":
        return any(phrase_in(v, val.replace("*", "")) for v in vals)
    if not phrase and re.search(r"(?<!\\)[*?]", val):
        rx = wildcard_re(val, False)
        return any(rx.fullmatch(str(v)) for v in vals)
    target = re.sub(r"\\(.)", r"\1", val)
    return any(str(v) == target for v in vals)


def eval_qs(node, doc):
    op = node[0]
    if op == "and":
        return eval_qs(node[1], doc) and eval_qs(node[2], doc)
    if op == "or":
        return eval_qs(node[1], doc) or eval_qs(node[2], doc)
    if op == "not":
        return not eval_qs(node[1], doc)
    if op == "field":
        return match_value(values(doc, node[1]), node[2], node[3], node[1])
    text = node[1]
    for path in ("rule.description", "agent.name", "rule.id", "location", "decoder.name", "data.srcip"):
        if match_value(values(doc, path), text, node[2], path):
            return True
    return any(phrase_in(v, text) for v in values(doc, "full_log"))


# ------------------------------------------------------------------ query DSL
def matches(q, doc):
    if not q:
        return True
    (kind, body), = q.items()
    if kind == "match_all":
        return True
    if kind == "bool":
        for c in body.get("filter", []) + body.get("must", []):
            if not matches(c, doc):
                return False
        for c in body.get("must_not", []):
            if matches(c, doc):
                return False
        should = body.get("should", [])
        if should:
            need = body.get("minimum_should_match", 1 if not (body.get("filter") or body.get("must")) else 0)
            if sum(1 for c in should if matches(c, doc)) < need:
                return False
        return True
    if kind == "range":
        (field, spec), = body.items()
        vs = values(doc, field)
        for v in vs:
            x = ts_ms(v) if field in ("timestamp", "@timestamp") else float(v)
            ok = True
            for k, lim in spec.items():
                if k in ("format", "time_zone"):
                    continue
                lim = ts_ms(lim) if field in ("timestamp", "@timestamp") else float(lim)
                ok &= {"gte": x >= lim, "gt": x > lim, "lte": x <= lim, "lt": x < lim}[k]
            if ok:
                return True
        return False
    if kind == "term":
        (field, val), = body.items()
        val = val.get("value") if isinstance(val, dict) else val
        return any(str(v) == str(val) for v in values(doc, field))
    if kind == "terms":
        (field, vals), = body.items()
        want = {str(v) for v in vals}
        return any(str(v) in want for v in values(doc, field))
    if kind == "wildcard":
        (field, spec), = body.items()
        rx = wildcard_re(spec["value"], spec.get("case_insensitive", False))
        return any(isinstance(v, str) and rx.fullmatch(v) for v in values(doc, field))
    if kind == "match_phrase":
        (field, val), = body.items()
        return any(phrase_in(v, val) for v in values(doc, field))
    if kind == "ids":
        return doc["__id"] in body["values"]
    if kind == "exists":
        return bool(values(doc, body["field"]))
    if kind == "query_string":
        return eval_qs(parse_query_string(body["query"]), doc)
    raise BadQuery(f"[{kind}] query is not supported by the mock")


def sort_docs(docs, sort):
    for spec in reversed(sort or []):
        (field, opt), = spec.items()
        order = opt.get("order", "asc") if isinstance(opt, dict) else opt
        def key(d, field=field):
            v = values(d, field)
            if not v:
                return float("-inf")
            return ts_ms(v[0]) if field in ("timestamp", "@timestamp") else (float(v[0]) if isinstance(v[0], (int, float)) else str(v[0]))
        docs = sorted(docs, key=key, reverse=order == "desc")
    return docs


def source_filter(doc, spec):
    src = {k: v for k, v in doc.items() if k != "__id"}
    if spec is True or spec is None:
        return src
    includes = spec if isinstance(spec, list) else spec.get("includes", [])
    if not includes:
        return src
    out = {}
    for path in includes:
        parts = path.split(".")
        cur, dst = src, out
        for i, p in enumerate(parts):
            if not isinstance(cur, dict) or p not in cur:
                break
            if i == len(parts) - 1:
                dst[p] = cur[p]
            else:
                dst = dst.setdefault(p, {})
                cur = cur[p]
    return out


UNITS = {"s": 1000, "m": 60000, "h": 3600000, "d": 86400000}


def aggregate(spec, docs):
    out = {}
    for name, a in (spec or {}).items():
        kind = next(k for k in a if k != "aggs")
        body, sub = a[kind], a.get("aggs")
        if kind == "date_histogram":
            iv = int(body["fixed_interval"][:-1]) * UNITS[body["fixed_interval"][-1]]
            buckets = {}
            for d in docs:
                for v in values(d, body["field"])[:1]:
                    k = ts_ms(v) // iv * iv
                    buckets.setdefault(k, []).append(d)
            if body.get("min_doc_count") == 0 and body.get("extended_bounds"):
                lo = int(body["extended_bounds"]["min"]) // iv * iv
                hi = int(body["extended_bounds"]["max"])
                for k in range(lo, hi + 1, iv):
                    buckets.setdefault(k, [])
            out[name] = {"buckets": [dict({"key": k, "key_as_string": str(k), "doc_count": len(ds)}, **aggregate(sub, ds))
                                     for k, ds in sorted(buckets.items())]}
        elif kind == "terms":
            counts = {}
            for d in docs:
                for v in dict.fromkeys(values(d, body["field"])):
                    counts.setdefault(v, []).append(d)
            if "include" in body:
                inc = {str(x) for x in body["include"]}
                counts = {k: v for k, v in counts.items() if str(k) in inc}
            top = sorted(counts.items(), key=lambda kv: (-len(kv[1]), str(kv[0])))[:body.get("size", 10)]
            out[name] = {"doc_count_error_upper_bound": 0, "sum_other_doc_count": 0,
                         "buckets": [dict({"key": k, "doc_count": len(ds)}, **aggregate(sub, ds)) for k, ds in top]}
        elif kind == "range":
            res = []
            for r in body["ranges"]:
                ds = [d for d in docs if any((r.get("from") is None or float(v) >= r["from"]) and
                                             (r.get("to") is None or float(v) < r["to"]) for v in values(d, body["field"]))]
                res.append(dict({"key": r.get("key", f"{r.get('from')}-{r.get('to')}"), "doc_count": len(ds)}, **aggregate(sub, ds)))
            out[name] = {"buckets": res}
        elif kind == "filter":
            ds = [d for d in docs if matches(body, d)]
            out[name] = dict({"doc_count": len(ds)}, **aggregate(sub, ds))
        elif kind == "max":
            vals = [ts_ms(v) if body["field"] in ("timestamp", "@timestamp") else float(v) for d in docs for v in values(d, body["field"])]
            out[name] = {"value": max(vals) if vals else None}
        elif kind == "top_hits":
            ds = sort_docs(docs, body.get("sort"))[:body.get("size", 3)]
            out[name] = {"hits": {"total": {"value": len(docs), "relation": "eq"},
                                  "hits": [{"_id": d["__id"], "_source": source_filter(d, body.get("_source"))} for d in ds]}}
        else:
            raise BadQuery(f"[{kind}] aggregation is not supported by the mock")
    return out


def search(pattern, body):
    names = [n for n in INDICES if any(fnmatch.fnmatch(n, p) for p in pattern.split(","))]
    docs = [d for n in names for d in INDICES[n]]
    q = body.get("query")
    hits = [d for d in docs if matches(q, d)]
    ordered = sort_docs(hits, body.get("sort"))
    start, size = body.get("from", 0), body.get("size", 10)
    if start + size > 10000:
        raise BadQuery("Result window is too large, from + size must be less than or equal to: [10000]")
    page = ordered[start:start + size]
    res = {"took": 3, "timed_out": False, "_shards": {"total": len(names) * 3, "successful": len(names) * 3, "skipped": 0, "failed": 0},
           "hits": {"total": {"value": len(hits), "relation": "eq"}, "max_score": None,
                    "hits": [{"_index": next(n for n in names if d in INDICES[n]), "_id": d["__id"], "_score": None,
                              "_source": source_filter(d, body.get("_source"))} for d in page]}}
    if body.get("aggs"):
        res["aggregations"] = aggregate(body["aggs"], hits)
    return res


def os_error(status, reason, typ="query_shard_exception"):
    return status, {"error": {"root_cause": [{"type": typ, "reason": reason}], "type": "search_phase_execution_exception",
                              "reason": "all shards failed", "phase": "query",
                              "failed_shards": [{"shard": 0, "index": "x", "reason": {"type": typ, "reason": "Failed to parse query",
                                                                                     "caused_by": {"type": "parse_exception", "reason": reason}}}]},
                    "status": status}


class Indexer(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def reply(self, status, obj):
        data = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    ADMIN_DN = "CN=admin,OU=Wazuh,O=Wazuh,L=California,C=US"

    def who(self):
        # like the OpenSearch security plugin: a client certificate listed in admin_dn is the super admin
        cert = self.connection.getpeercert() if hasattr(self.connection, "getpeercert") else None
        if cert:
            parts = [f"{k.upper() if k != 'commonName' else 'CN'}={v}" for rdn in reversed(cert.get("subject", ())) for k, v in rdn]
            dn = ",".join(p.replace("ORGANIZATIONALUNITNAME", "OU").replace("ORGANIZATIONNAME", "O").replace("LOCALITYNAME", "L")
                          .replace("COUNTRYNAME", "C") for p in parts)
            STATE.setdefault("cert_logins", []).append(dn)
            if dn == self.ADMIN_DN:
                return dn
        h = self.headers.get("Authorization", "")
        if not h.startswith("Basic "):
            return None
        user, _, pw = base64.b64decode(h[6:]).decode().partition(":")
        if user == "admin" and pw == STATE["admin_pass"]:
            return "admin"
        u = STATE["users"].get(user)
        return user if u and u["password"] == pw else None

    def handle_any(self, method):
        url = urlparse(self.path)
        user = self.who()
        STATE["requests"].append((method, url.path, user))
        if not user:
            return self.reply(401, {"error": "Unauthorized"})
        length = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(length) or b"{}") if length else {}
        path = unquote(url.path)
        if path == "/":
            return self.reply(200, {"name": "node-1", "version": {"distribution": "opensearch", "number": "2.19.1"}})
        if path == "/_cluster/health":
            return self.reply(200, {"cluster_name": "wazuh-cluster", "status": "green"})
        if path.startswith("/_plugins/_security/"):
            if path == "/_plugins/_security/authinfo":
                return self.reply(200, {"user_name": user, "roles": [r for r, m in STATE["mappings"].items() if user in m]})
            if user not in ("admin", self.ADMIN_DN):
                return self.reply(403, {"status": "FORBIDDEN", "message": "no permissions"})
            m = re.match(r"^/_plugins/_security/api/(roles|internalusers|rolesmapping)/([\w.-]+)$", path)
            if not m:
                return self.reply(404, {"status": "NOT_FOUND"})
            store = {"roles": STATE["roles"], "internalusers": STATE["users"], "rolesmapping": STATE["mappings"]}[m.group(1)]
            if method == "PUT":
                if m.group(1) == "internalusers":
                    if len(body.get("password", "")) < 8:
                        return self.reply(400, {"status": "error", "reason": "Weak password"})
                    store[m.group(2)] = {"password": body["password"]}
                elif m.group(1) == "rolesmapping":
                    store[m.group(2)] = body.get("users", [])
                else:
                    store[m.group(2)] = body
                return self.reply(200, {"status": "CREATED", "message": f"'{m.group(2)}' created."})
            if method == "DELETE":
                existed = store.pop(m.group(2), None)
                return self.reply(200 if existed is not None else 404, {"status": "OK" if existed is not None else "NOT_FOUND"})
            if method == "GET":
                return self.reply(200, {m.group(2): store[m.group(2)]}) if m.group(2) in store else self.reply(404, {"status": "NOT_FOUND"})
        m = re.match(r"^/([^/]+)/_search$", path)
        if m and method == "POST":
            if user != "admin":
                allowed = [p for r, users in STATE["mappings"].items() if user in users
                           for ip in STATE["roles"].get(r, {}).get("index_permissions", []) for p in ip["index_patterns"]]
                if not all(any(fnmatch.fnmatch(want, p) or want == p for p in allowed) for want in m.group(1).split(",")):
                    return self.reply(403, {"error": {"type": "security_exception", "reason": f"no permissions for [indices:data/read/search] and User [name={user}]"}, "status": 403})
            try:
                return self.reply(200, search(m.group(1), body))
            except BadQuery as e:
                return self.reply(*os_error(400, str(e)))
        return self.reply(404, {"error": "not found"})

    def do_GET(self):
        self.handle_any("GET")

    def do_POST(self):
        self.handle_any("POST")

    def do_PUT(self):
        self.handle_any("PUT")

    def do_DELETE(self):
        self.handle_any("DELETE")


# ------------------------------------------------------------------ Wazuh server API
API = {"users": {1: {"username": "wazuh", "password": "demo-only-1A*", "roles": [1]},
                 2: {"username": "wazuh-wui", "password": "demo-only-1A*", "roles": [1]}},
       "tokens": {}, "next": 100}
ROLES = [{"id": 1, "name": "administrator"}, {"id": 2, "name": "readonly"}, {"id": 3, "name": "users_admin"},
         {"id": 4, "name": "agents_readonly"}]
NOW_S = lambda: datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")
AGO_S = lambda s: (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=s)).strftime("%Y-%m-%dT%H:%M:%S+00:00")
AGENTS = [{"id": "000", "name": "wazuh-server", "ip": "127.0.0.1", "status": "active", "os": {"name": "Ubuntu", "version": "24.04.1 LTS", "platform": "ubuntu"},
           "version": "Wazuh v4.12.0", "lastKeepAlive": "9999-12-31T23:59:59+00:00", "dateAdd": "2026-10-20T09:00:00+00:00", "node_name": "node01"},
          {"id": "001", "name": "Windows-10", "ip": "192.168.56.131", "status": "active", "os": {"name": "Microsoft Windows 10 Pro", "version": "10.0.19045.5131", "platform": "windows"},
           "version": "Wazuh v4.12.0", "group": ["default"], "dateAdd": "2026-10-21T10:00:00+00:00", "node_name": "node01", "registerIP": "any"},
          {"id": "002", "name": "Ubuntu", "ip": "192.168.56.129", "status": "disconnected", "os": {"name": "Ubuntu", "version": "24.04.1 LTS", "platform": "ubuntu"},
           "version": "Wazuh v4.12.0", "group": ["default", "web"], "dateAdd": "2026-10-21T10:30:00+00:00", "node_name": "node01", "registerIP": "any"}]
SCA = {"001": [{"policy_id": "cis_win10_enterprise", "name": "CIS Microsoft Windows 10 Enterprise Benchmark v3.0.0", "pass": 132, "fail": 228, "invalid": 4, "total_checks": 364, "score": 36, "end_scan": "2026-11-12T02:10:00+00:00"}],
       "002": [{"policy_id": "cis_ubuntu24-04", "name": "CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0", "pass": 99, "fail": 137, "invalid": 0, "total_checks": 236, "score": 42, "end_scan": "2026-11-12T03:00:00+00:00"}],
       "000": [{"policy_id": "cis_ubuntu24-04", "name": "CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0", "pass": 120, "fail": 116, "invalid": 0, "total_checks": 236, "score": 51, "end_scan": "2026-11-12T03:00:00+00:00"}]}
PW_RE = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,}$')


class Api(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def reply(self, status, obj):
        data = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def items(self, items):
        return self.reply(200, {"data": {"affected_items": items, "total_affected_items": len(items), "total_failed_items": 0,
                                         "failed_items": []}, "message": "ok", "error": 0})

    def handle_any(self, method):
        url = urlparse(self.path)
        q = parse_qs(url.query)
        STATE["requests"].append(("API " + method, url.path, None))
        length = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(length) or b"{}") if length else {}
        auth = self.headers.get("Authorization", "")
        if url.path == "/security/user/authenticate" and method == "POST":
            if not auth.startswith("Basic "):
                return self.reply(401, {"title": "Unauthorized", "detail": "Invalid credentials"})
            name, _, pw = base64.b64decode(auth[6:]).decode().partition(":")
            uid = next((i for i, u in API["users"].items() if u["username"] == name and u["password"] == pw), None)
            if not uid:
                return self.reply(401, {"title": "Unauthorized", "detail": "Invalid credentials"})
            tok = secrets.token_hex(16)
            API["tokens"][tok] = uid
            return self.reply(200, {"data": {"token": tok}, "error": 0})
        uid = API["tokens"].get(auth[7:]) if auth.startswith("Bearer ") else None
        if not uid:
            return self.reply(401, {"title": "Unauthorized", "detail": "No authorization token provided"})
        admin = 1 in API["users"][uid]["roles"]
        if url.path.startswith("/security/"):
            if not admin:
                return self.reply(403, {"title": "Permission Denied", "detail": "RBAC"})
            if url.path == "/security/users" and method == "GET":
                return self.items([{"id": i, "username": u["username"], "roles": u["roles"]} for i, u in API["users"].items()])
            if url.path == "/security/users" and method == "POST":
                if not PW_RE.match(body.get("password", "")):
                    return self.reply(400, {"title": "Bad Request", "detail": "Invalid password provided"})
                if any(u["username"] == body["username"] for u in API["users"].values()):
                    return self.reply(200, {"data": {"affected_items": [], "failed_items": [{"error": {"code": 5000}}]}, "error": 1})
                API["next"] += 1
                API["users"][API["next"]] = {"username": body["username"], "password": body["password"], "roles": []}
                return self.items([{"id": API["next"], "username": body["username"], "roles": []}])
            if url.path == "/security/users" and method == "DELETE":
                for i in q.get("user_ids", [""])[0].split(","):
                    API["users"].pop(int(i), None) if i.isdigit() else None
                return self.items([])
            m = re.match(r"^/security/users/(\d+)$", url.path)
            if m and method == "PUT":
                if not PW_RE.match(body.get("password", "")):
                    return self.reply(400, {"title": "Bad Request", "detail": "Invalid password provided"})
                API["users"][int(m.group(1))]["password"] = body["password"]
                return self.items([{"id": int(m.group(1))}])
            m = re.match(r"^/security/users/(\d+)/roles$", url.path)
            if m and method == "POST":
                API["users"][int(m.group(1))]["roles"] = sorted(set(API["users"][int(m.group(1))]["roles"]) |
                                                                {int(r) for r in q.get("role_ids", [""])[0].split(",") if r})
                return self.items([{"id": int(m.group(1))}])
            if url.path == "/security/roles" and method == "GET":
                return self.items(ROLES)
            return self.reply(404, {"title": "Not found"})
        if method != "GET":
            return self.reply(405, {"title": "Method not allowed"})
        if url.path == "/agents":
            wanted = q.get("agents_list", [""])[0].split(",") if "agents_list" in q else None
            items = [dict(a, lastKeepAlive=a.get("lastKeepAlive") if a["id"] == "000" else (NOW_S() if a.get("status") == "active" else AGO_S(5400))) for a in AGENTS
                     if wanted is None or a["id"] in wanted]
            return self.items(items)
        if url.path == "/agents/summary/status":
            return self.reply(200, {"data": {"connection": {"active": 2, "disconnected": 1, "never_connected": 0, "pending": 0, "total": 3},
                                             "configuration": {"synced": 3, "not_synced": 0, "total": 3}}, "error": 0})
        if url.path == "/manager/info":
            return self.items([{"path": "/var/ossec", "version": "v4.12.0", "type": "server", "max_agents": "unlimited",
                                "openssl_support": "yes", "tz_offset": "+0300", "tz_name": "Asia/Riyadh"}])
        if url.path == "/manager/status":
            return self.items([{"wazuh-agentlessd": "stopped", "wazuh-analysisd": "running", "wazuh-authd": "running",
                                "wazuh-csyslogd": "stopped", "wazuh-dbd": "stopped", "wazuh-monitord": "running",
                                "wazuh-execd": "running", "wazuh-integratord": "running", "wazuh-logcollector": "running",
                                "wazuh-maild": "stopped", "wazuh-remoted": "running", "wazuh-reportd": "stopped",
                                "wazuh-syscheckd": "running", "wazuh-clusterd": "stopped", "wazuh-modulesd": "running",
                                "wazuh-db": "running", "wazuh-apid": "running"}])
        m = re.match(r"^/sca/(\d+)$", url.path)
        if m:
            return self.items(SCA.get(m.group(1), []))
        m = re.match(r"^/syscollector/(\d+)/(os|hardware)$", url.path)
        if m:
            if m.group(2) == "os":
                a = next((a for a in AGENTS if a["id"] == m.group(1)), None)
                return self.items([{"os": {"name": a["os"]["name"], "version": a["os"]["version"]}, "hostname": a["name"],
                                    "architecture": "x86_64"}] if a else [])
            return self.items([{"cpu": {"name": "Intel(R) Core(TM) i7-1165G7 @ 2.80GHz", "cores": 2},
                                "ram": {"total": 4019304, "free": 1210044, "usage": 70}}])
        return self.reply(404, {"title": "Not found"})

    def do_GET(self):
        self.handle_any("GET")

    def do_POST(self):
        self.handle_any("POST")

    def do_PUT(self):
        self.handle_any("PUT")

    def do_DELETE(self):
        self.handle_any("DELETE")


def serve(handler, port, cert, key, client_ca=None):
    srv = ThreadingHTTPServer(("127.0.0.1", port), handler)
    if "--plain" in sys.argv:
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    if client_ca:          # OpenSearch's default plugins.security.ssl.http.clientauth_mode: OPTIONAL
        ctx.verify_mode = ssl.CERT_OPTIONAL
        ctx.load_verify_locations(client_ca)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()


if __name__ == "__main__":
    serve(Indexer, 19200, f"{CERTS}/indexer.pem", f"{CERTS}/indexer-key.pem", None if "--no-client-certs" in sys.argv else f"{CERTS}/root-ca.pem")
    serve(Api, 15500, f"{CERTS}/api.pem", f"{CERTS}/api-key.pem")
    print(f"mock indexer https://127.0.0.1:19200 ({sum(len(v) for v in INDICES.values())} docs), mock API https://127.0.0.1:15500", flush=True)
    while True:
        time.sleep(3600)
