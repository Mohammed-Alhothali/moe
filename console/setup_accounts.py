#!/usr/bin/env python3
"""Connects the MOE console to Wazuh with two least-privilege accounts. Run by install-console.sh as root.

  * Wazuh indexer: role "moe_console_read" (read the alert, archive, vulnerability and monitoring indices, plus
    cluster health) and internal user "moe_console" mapped to it. Made with the indexer's security REST API,
    authenticated with the indexer's own admin certificate (/etc/wazuh-indexer/certs/admin.pem, readable only by
    root, the same certificate Wazuh's password tool uses), so nobody has to type a password. Only if that
    certificate is missing or refused, it asks for the dashboard admin login once. Nothing of either is stored.
  * Wazuh server API: user "moe-console" with Wazuh's built-in "readonly" role. Made with the API account the
    Wazuh dashboard already uses (read from its wazuh.yml), or one you type. Never stored either.

The two new passwords are random, written only to /etc/moe-console/console.env (root:moe-console, 0640).
Existing working accounts are kept unless --force is given.

Usage:
  setup_accounts.py --env FILE --indexer URL --ca FILE --api URL [--wazuh-yml FILE] [--admin-cert F --admin-key F] [--force]
  setup_accounts.py --env FILE --remove [--wazuh-yml FILE]
"""
import argparse, base64, getpass, hashlib, http.client, json, os, re, secrets, ssl, string, sys, time
from urllib.parse import urlencode, urlparse

ROLE, IX_USER, API_USER = "moe_console_read", "moe_console", "moe-console"
ROLE_BODY = {
    "description": "MOE SOC console: read-only access to Wazuh alerts, archives and state indices",
    "cluster_permissions": ["cluster_monitor", "cluster_composite_ops_ro"],
    "index_permissions": [{"index_patterns": ["wazuh-alerts-*", "wazuh-archives-*", "wazuh-states-vulnerabilities-*",
                                              "wazuh-monitoring-*", "wazuh-statistics-*"],
                           "allowed_actions": ["read", "indices_monitor"]}],
    "tenant_permissions": []}


def say(text):
    print(f"   {text}", flush=True)


def new_password(n=24):
    pools = [string.ascii_uppercase, string.ascii_lowercase, string.digits, "-_.@+="]
    chars = [secrets.choice(p) for p in pools] + [secrets.choice("".join(pools)) for _ in range(n - len(pools))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def read_env(path):
    out = {}
    if os.path.exists(path):
        for line in open(path):
            m = re.match(r"^([A-Z_]+)=(.*)$", line.rstrip("\n"))
            if m:
                v = m.group(2)
                out[m.group(1)] = v[1:-1] if len(v) >= 2 and v[0] == v[-1] == "'" else v
    return out


def write_env(path, values):
    lines, seen = [], set()
    if os.path.exists(path):
        for line in open(path):
            m = re.match(r"^([A-Z_]+)=", line)
            if m and m.group(1) in values:
                if values[m.group(1)] is not None:
                    lines.append(f"{m.group(1)}='{values[m.group(1)]}'\n")
                seen.add(m.group(1))
            else:
                lines.append(line if line.endswith("\n") else line + "\n")
    for k, v in values.items():
        if k not in seen and v is not None:
            lines.append(f"{k}='{v}'\n")
    for k, v in values.items():
        if v is not None and ("'" in v or "\n" in v):
            sys.exit(f"!! refusing to write a value with a quote or newline for {k}")
    tmp = path + ".tmp"
    old = os.umask(0o027)
    try:
        with open(tmp, "w") as f:
            f.writelines(lines)
        os.chmod(tmp, 0o640)
        st = os.stat(path) if os.path.exists(path) else None
        if st:
            os.chown(tmp, st.st_uid, st.st_gid)
        os.replace(tmp, path)
    finally:
        os.umask(old)


def https(url, method, path, body=None, auth=None, ca=None, pin=None, timeout=20, client=None):
    u = urlparse(url)
    if ca:
        ctx = ssl.create_default_context(cafile=ca)
        ctx.check_hostname = False
        ctx.verify_flags &= ~getattr(ssl, "VERIFY_X509_STRICT", 0)
    else:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    if client:                      # TLS client certificate (the indexer's admin certificate)
        ctx.load_cert_chain(client[0], client[1])
    conn = http.client.HTTPSConnection(u.hostname, u.port or 443, context=ctx, timeout=timeout)
    try:
        conn.connect()
        if pin:
            der = conn.sock.getpeercert(binary_form=True)
            if hashlib.sha256(der).hexdigest() != pin:
                raise RuntimeError("certificate does not match the pinned fingerprint")
        headers = {"Accept": "application/json"}
        if auth:
            headers["Authorization"] = auth
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        conn.request(method, path, body=data, headers=headers)
        r = conn.getresponse()
        raw = r.read()
        try:
            return r.status, json.loads(raw or b"{}")
        except ValueError:
            return r.status, {"text": raw[:300].decode("utf-8", "replace")}
    finally:
        conn.close()


def basic(user, password):
    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()


def cert_pin(url):
    u = urlparse(url)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    conn = http.client.HTTPSConnection(u.hostname, u.port or 443, context=ctx, timeout=10)
    try:
        conn.connect()
        return hashlib.sha256(conn.sock.getpeercert(binary_form=True)).hexdigest()
    finally:
        conn.close()


# ------------------------------------------------------------------ indexer
def indexer_works(env):
    url, user, pw, ca = env.get("MOE_INDEXER_URL"), env.get("MOE_INDEXER_USER"), env.get("MOE_INDEXER_PASS"), env.get("MOE_INDEXER_CA")
    if not (url and user and pw and ca and os.path.exists(ca)):
        return False
    try:
        st, _ = https(url, "POST", "/wazuh-alerts-*/_search?ignore_unavailable=true&allow_no_indices=true", {"size": 0},
                      basic(user, pw), ca=ca)
        return st == 200
    except Exception:
        return False


def admin_certificate(args):
    """The indexer's admin certificate, if this server has it and the indexer accepts it for its security API."""
    cert, key = args.admin_cert, args.admin_key
    if not (cert and key and os.path.isfile(cert) and os.path.isfile(key)):
        return None
    try:
        st, body = https(args.indexer, "GET", "/_plugins/_security/authinfo", ca=args.ca, client=(cert, key))
    except Exception as e:
        say(f"indexer: the admin certificate could not be used ({e.__class__.__name__}); asking for the login instead")
        return None
    if st != 200:
        return None
    say(f"indexer: signed in with the indexer's admin certificate ({cert}); no password needed")
    return (cert, key)


def admin_login(args, intro=True):
    """Fallback: the dashboard admin login, typed by the person running the installer (three tries)."""
    if intro:
        print("   The console needs its own read-only account in the Wazuh indexer. To create it, type the login you use")
        print("   for the Wazuh dashboard. It is used once and not saved. Press Enter at the password to skip.")
    user = input("   Dashboard user name (press Enter for admin): ").strip() or "admin"
    for attempt in range(3):
        if not sys.stdin.isatty():
            password = sys.stdin.readline().rstrip("\n")
        else:
            password = getpass.getpass(f"   Password for {user} (not shown): ")
        if not password:
            return None
        auth = basic(user, password)
        try:
            st, _ = https(args.indexer, "GET", "/_plugins/_security/authinfo", auth=auth, ca=args.ca)
        except Exception as e:
            say(f"!! indexer: cannot reach {args.indexer} ({e.__class__.__name__}: {e})")
            return None
        if st == 200:
            return auth
        say(f"!! that login was refused (HTTP {st})." + (" Try again." if attempt < 2 else ""))
    return None


def connect_indexer(args, env):
    if not args.force and indexer_works(env):
        say("indexer: the console's read-only account already works, keeping it")
        return {}
    client = admin_certificate(args)
    auth = None if client else admin_login(args)
    if not client and not auth:
        say("indexer: skipped. Overview, Alerts, Logs and ATT&CK stay off until you run: sudo bash install-console.sh --connect")
        return {}
    pw = new_password()
    steps = [("PUT", f"/_plugins/_security/api/roles/{ROLE}", ROLE_BODY),
             ("PUT", f"/_plugins/_security/api/internalusers/{IX_USER}",
              {"password": pw, "backend_roles": [], "attributes": {"purpose": "MOE SOC console, read-only"}}),
             ("PUT", f"/_plugins/_security/api/rolesmapping/{ROLE}", {"users": [IX_USER]})]
    for method, path, body in steps:
        st, res = https(args.indexer, method, path, body, auth, ca=args.ca, client=client)
        if st not in (200, 201):
            say(f"!! indexer: {method} {path} failed (HTTP {st}): {json.dumps(res)[:300]}")
            return {}
    for _ in range(10):
        st, _ = https(args.indexer, "POST", "/wazuh-alerts-*/_search?ignore_unavailable=true&allow_no_indices=true",
                      {"size": 0}, basic(IX_USER, pw), ca=args.ca)
        if st == 200:
            say(f"indexer: read-only user '{IX_USER}' with role '{ROLE}' is ready")
            return {"MOE_INDEXER_URL": args.indexer, "MOE_INDEXER_USER": IX_USER, "MOE_INDEXER_PASS": pw, "MOE_INDEXER_CA": args.ca}
        time.sleep(1)
    say(f"!! indexer: the new account was created but cannot search yet (HTTP {st}). Run --connect again in a minute.")
    return {}


# ------------------------------------------------------------------ server API
def wazuh_yml_login(path):
    try:
        text = open(path).read()
    except OSError:
        return None
    block = text.split("hosts:", 1)[-1]
    get = lambda key: (re.search(rf"^\s*{key}:\s*(.+?)\s*$", block, re.M) or [None, None])[1]
    url, port, user, pw = get("url"), get("port"), get("username"), get("password")
    unq = lambda v: v[1:-1] if v and len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"" else v
    if not (url and user and pw):
        return None
    return {"url": f"{unq(url).rstrip('/')}:{unq(port) or 55000}", "user": unq(user), "password": unq(pw)}


def api_token(url, user, password, pin):
    st, body = https(url, "POST", "/security/user/authenticate", auth=basic(user, password), pin=pin)
    return (body.get("data") or {}).get("token") if st == 200 else None


def api_works(env):
    url, user, pw, pin = env.get("MOE_API_URL"), env.get("MOE_API_USER"), env.get("MOE_API_PASS"), env.get("MOE_API_PIN")
    if not (url and user and pw and pin):
        return False
    try:
        tok = api_token(url, user, pw, pin)
        if not tok:
            return False
        st, _ = https(url, "GET", "/agents?limit=1", auth="Bearer " + tok, pin=pin)
        return st == 200
    except Exception:
        return False


def connect_api(args, env):
    if not args.force and api_works(env):
        say("server API: the console's read-only API user already works, keeping it")
        return {}
    try:
        pin = cert_pin(args.api)
    except Exception as e:
        say(f"!! server API: cannot reach {args.api} ({e.__class__.__name__}). Agents will come from alerts only.")
        return {}
    login = wazuh_yml_login(args.wazuh_yml)
    if login:
        say(f"server API: using the dashboard's API account '{login['user']}' (from {args.wazuh_yml}) to create the console's user")
        user, password = login["user"], login["password"]
    else:
        print("   The Wazuh dashboard's API settings were not found. Type a Wazuh API administrator login")
        print("   (default user wazuh-wui), or press Enter to skip.")
        user = input("   API admin user [wazuh-wui]: ").strip() or "wazuh-wui"
        password = getpass.getpass("   API admin password (not shown): ") if sys.stdin.isatty() else sys.stdin.readline().rstrip("\n")
        if not password:
            say("server API: skipped. Agents will come from alerts only until you run --connect")
            return {}
    tok = api_token(args.api, user, password, pin)
    if not tok:
        say("!! server API: that API login was refused. Nothing was changed.")
        return {}
    auth = "Bearer " + tok
    st, body = https(args.api, "GET", "/security/users?" + urlencode({"limit": 500}), auth=auth, pin=pin)
    users = (body.get("data") or {}).get("affected_items") or []
    existing = next((u for u in users if u.get("username") == API_USER), None)
    pw = new_password()
    if existing:
        uid = existing["id"]
        st, body = https(args.api, "PUT", f"/security/users/{uid}", {"password": pw}, auth, pin=pin)
    else:
        st, body = https(args.api, "POST", "/security/users", {"username": API_USER, "password": pw}, auth, pin=pin)
        items = (body.get("data") or {}).get("affected_items") or []
        uid = items[0]["id"] if items else None
    if st != 200 or uid is None:
        say(f"!! server API: could not create or update '{API_USER}' (HTTP {st}): {json.dumps(body)[:300]}")
        return {}
    st, body = https(args.api, "GET", "/security/roles?" + urlencode({"limit": 500}), auth=auth, pin=pin)
    role = next((r for r in (body.get("data") or {}).get("affected_items") or [] if r.get("name") == "readonly"), None)
    if not role:
        say("!! server API: Wazuh's built-in 'readonly' role was not found")
        return {}
    if role["id"] not in (existing or {}).get("roles", []):
        st, body = https(args.api, "POST", f"/security/users/{uid}/roles?" + urlencode({"role_ids": role["id"]}), None, auth, pin=pin)
        if st != 200:
            say(f"!! server API: could not give '{API_USER}' the readonly role (HTTP {st})")
            return {}
    for _ in range(10):
        if api_works({"MOE_API_URL": args.api, "MOE_API_USER": API_USER, "MOE_API_PASS": pw, "MOE_API_PIN": pin}):
            say(f"server API: read-only user '{API_USER}' is ready (certificate pinned)")
            return {"MOE_API_URL": args.api, "MOE_API_USER": API_USER, "MOE_API_PASS": pw, "MOE_API_PIN": pin}
        time.sleep(1)
    say("!! server API: the user was created but cannot read agents yet. Run --connect again in a minute.")
    return {}


# ------------------------------------------------------------------ removal (used by --uninstall)
def remove(args, env):
    login = wazuh_yml_login(args.wazuh_yml)
    if env.get("MOE_API_URL"):
        try:
            if not login:
                raise RuntimeError("the dashboard's API account was not found")
            pin = cert_pin(env["MOE_API_URL"])
            tok = api_token(env["MOE_API_URL"], login["user"], login["password"], pin)
            if not tok:
                raise RuntimeError("the dashboard's API account was refused")
            st, body = https(env["MOE_API_URL"], "GET", "/security/users?limit=500", auth="Bearer " + tok, pin=pin)
            u = next((u for u in (body.get("data") or {}).get("affected_items") or [] if u.get("username") == API_USER), None)
            if not u:
                say(f"server API: user '{API_USER}' was not there")
            else:
                st, _ = https(env["MOE_API_URL"], "DELETE", f"/security/users?user_ids={u['id']}", auth="Bearer " + tok, pin=pin)
                if st != 200:
                    raise RuntimeError(f"HTTP {st}")
                say(f"server API: removed user '{API_USER}'")
        except Exception as e:
            say(f"server API: could not remove '{API_USER}' ({e}); remove it in Server management > Security > Users")
    if env.get("MOE_INDEXER_URL"):
        args.indexer = env["MOE_INDEXER_URL"]
        args.ca = env.get("MOE_INDEXER_CA") if os.path.exists(env.get("MOE_INDEXER_CA", "")) else None
        client = admin_certificate(args)
        auth = None
        if not client:
            print("   To also remove the console's indexer account, type the dashboard admin login (Enter to keep it).")
            auth = admin_login(args, intro=False) if sys.stdin.isatty() else None
        if not client and not auth:
            say(f"indexer: kept user '{IX_USER}'. Remove it later in Indexer management > Security > Internal users")
            return
        outcome = []
        for kind, path in (("role mapping", f"/_plugins/_security/api/rolesmapping/{ROLE}"),
                           ("user", f"/_plugins/_security/api/internalusers/{IX_USER}"),
                           ("role", f"/_plugins/_security/api/roles/{ROLE}")):
            try:
                st, _ = https(args.indexer, "DELETE", path, auth=auth, ca=args.ca, client=client)
            except Exception as e:
                st = e.__class__.__name__
            outcome.append(f"{kind} {'removed' if st == 200 else 'was not there' if st == 404 else f'not removed ({st})'}")
        say("indexer: " + ", ".join(outcome))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--env", required=True)
    ap.add_argument("--indexer")
    ap.add_argument("--ca")
    ap.add_argument("--api")
    ap.add_argument("--wazuh-yml", default="/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml")
    ap.add_argument("--admin-cert", default="/etc/wazuh-indexer/certs/admin.pem")
    ap.add_argument("--admin-key", default="/etc/wazuh-indexer/certs/admin-key.pem")
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--remove", action="store_true")
    args = ap.parse_args()
    env = read_env(args.env)
    if args.remove:
        remove(args, env)
        return
    updates = {}
    if args.indexer and args.ca:
        updates.update(connect_indexer(args, env))
    if args.api:
        updates.update(connect_api(args, env))
    if updates:
        write_env(args.env, updates)


if __name__ == "__main__":
    main()
