#!/usr/bin/env python3
"""Rifadah Pilgrim Services Portal (fictional organisation) - lab application.

A normal, secure business application. Its job in this lab is to write a rich security audit
log for the SIEM: every security-relevant action becomes one line in PORTAL_LOG, e.g.

  Nov 10 20:15:03 web01 pilgrim-portal[812]: {"event":"login_failed","srcip":"203.0.113.9",...}

The syslog-style header lets Wazuh pre-decode program_name=pilgrim-portal; the custom decoder
(wazuh/decoders/pp-pilgrim_portal_decoders.xml) turns the JSON body into rule fields.

Security posture (the app is NOT deliberately vulnerable):
  * parameterized SQL everywhere, role-scoped record access, CSRF tokens on every form
  * uploads: extension allowlist + magic-byte check + random server-side names, stored outside the web root
  * listens on 127.0.0.1 only; nginx is the single client and supplies the real client IP in X-Real-IP
Detection complements these controls: the SIEM catches abuse of legitimate features
(bots, stuffing, harvesting, price overrides, bulk exports) that no input validation can stop.
"""
import csv
import io
import ipaddress
import json
import os
import secrets
import socket
import sqlite3
import threading
import time
import urllib.request
import uuid
from functools import wraps

from flask import (Flask, Response, abort, flash, g, redirect, render_template, request,
                   session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

BASE = os.path.dirname(os.path.abspath(__file__))
ORG = os.environ.get("PORTAL_ORG", "Rifadah Pilgrim Services")
DB_PATH = os.environ.get("PORTAL_DB", os.path.join(BASE, "data", "portal.db"))
LOG_PATH = os.environ.get("PORTAL_LOG", os.path.join(BASE, "data", "portal.log"))
DOCS_DIR = os.environ.get("PORTAL_DOCS", os.path.join(BASE, "data", "documents"))
GEO_DB = os.environ.get("PORTAL_GEO_DB", os.path.join(BASE, "geo", "country.mmdb"))
LAB_COUNTRY = os.environ.get("PORTAL_LAB_COUNTRY", "SA")      # country reported for private/lab IPs
GEO_ONLINE = os.environ.get("PORTAL_GEO_ONLINE", "1") == "1"   # fall back to ip-api.com if no local DB

app = Flask(__name__, static_folder="static")
app.config.update(
    SECRET_KEY=os.environ.get("PORTAL_SECRET_KEY") or secrets.token_hex(32),
    MAX_CONTENT_LENGTH=5 * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

# --------------------------------------------------------------------------------------------
# Audit log
# --------------------------------------------------------------------------------------------
_HOST = socket.gethostname().split(".")[0]
_LOG_LOCK = threading.Lock()
_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


def _clean(value, limit=300):
    text = "" if value is None else str(value)
    return text.replace("\r", " ").replace("\n", " ")[:limit]


def audit(event, **fields):
    """Append one audit event: syslog header + compact JSON.

    Key names deliberately avoid Wazuh's reserved static fields (user, status, action, id, url,
    data...) except srcip, which is meant to land in the static source-IP field.
    """
    record = {
        "event": event,
        "srcip": client_ip(),
        "username": session.get("username", "-"),
        "role": session.get("role", "anonymous"),
        "country": session.get("country", "-"),
    }
    record.update({k: _clean(v) for k, v in fields.items() if v is not None})
    record["session"] = session.get("sid", "-")
    record["ua"] = _clean(request.headers.get("User-Agent", "-"), 160)
    now = time.localtime()
    header = (f"{_MONTHS[now.tm_mon - 1]} {now.tm_mday:>2} {time.strftime('%H:%M:%S', now)} "
              f"{_HOST} pilgrim-portal[{os.getpid()}]:")
    line = f"{header} {json.dumps(record, separators=(',', ':'))}\n"
    with _LOG_LOCK:
        with open(LOG_PATH, "a", encoding="utf-8") as fh:
            fh.write(line)


# --------------------------------------------------------------------------------------------
# Client IP and country
# --------------------------------------------------------------------------------------------
def client_ip():
    # gunicorn listens on 127.0.0.1 only, so nginx is the only client; it sets X-Real-IP.
    return (request.headers.get("X-Real-IP") or request.remote_addr or "-").strip()


_geo_reader = None
_geo_cache = {}


def _reader():
    global _geo_reader
    if _geo_reader is None:
        try:
            import maxminddb
            _geo_reader = maxminddb.open_database(GEO_DB) if os.path.exists(GEO_DB) else False
        except Exception:
            _geo_reader = False
    return _geo_reader or None


def country_of(ip):
    """ISO country code for an IP: local DB-IP/MaxMind database first, ip-api.com as fallback."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "ZZ"
    if addr.is_private or addr.is_loopback or addr.is_link_local:
        return LAB_COUNTRY
    if ip in _geo_cache:
        return _geo_cache[ip]
    code = None
    reader = _reader()
    if reader:
        try:
            code = ((reader.get(ip) or {}).get("country") or {}).get("iso_code")
        except Exception:
            code = None
    if not code and GEO_ONLINE:
        try:
            with urllib.request.urlopen(f"http://ip-api.com/json/{ip}?fields=countryCode", timeout=2) as resp:
                code = json.load(resp).get("countryCode")
        except Exception:
            code = None
    code = (code or "ZZ").upper()
    _geo_cache[ip] = code
    return code


# --------------------------------------------------------------------------------------------
# Database, auth, CSRF
# --------------------------------------------------------------------------------------------
def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH, timeout=10)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def _close_db(_exc):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


_DUMMY_HASH = generate_password_hash("timing-equaliser")


def login_required(*roles):
    def decorator(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            if "username" not in session:
                return redirect(url_for("login"))
            if roles and session.get("role") not in roles:
                abort(403)
            return view(*args, **kwargs)
        return wrapper
    return decorator


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(24)
    return session["csrf"]


@app.before_request
def _csrf_protect():
    if request.method == "POST":
        expected = session.get("csrf")
        if not expected or not secrets.compare_digest(expected, request.form.get("csrf", "")):
            abort(400)


@app.context_processor
def _template_globals():
    return {"ORG": ORG, "csrf_token": csrf_token}


def mask_passport(value):
    return value[:1] + "*" * (len(value) - 5) + value[-4:] if value and len(value) > 5 else "****"


app.jinja_env.filters["mask"] = mask_passport


# --------------------------------------------------------------------------------------------
# Pages
# --------------------------------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()[:80]
        password = request.form.get("password", "")
        user = db().execute(
            "SELECT username, password_hash, role, full_name, agency_code FROM users "
            "WHERE username = ? AND active = 1", (username,)).fetchone()
        country = country_of(client_ip())
        valid = check_password_hash(user["password_hash"] if user else _DUMMY_HASH, password)
        if user is None or not valid:
            audit("login_failed", username=username or "-", role="anonymous", country=country,
                  reason="unknown_user" if user is None else "bad_password")
            flash("Invalid username or password.", "error")
            return render_template("login.html"), 401
        session.clear()
        session.update(username=user["username"], role=user["role"], name=user["full_name"],
                       agency=user["agency_code"], country=country, sid=secrets.token_hex(4))
        csrf_token()
        audit("login_success")
        return redirect(url_for("dashboard"))
    return render_template("login.html")


@app.route("/logout")
def logout():
    if "username" in session:
        audit("logout")
    session.clear()
    return redirect(url_for("index"))


@app.route("/dashboard")
@login_required()
def dashboard():
    return render_template("dashboard.html")


@app.route("/bookings", methods=["GET", "POST"])
@login_required("pilgrim", "agency")
def bookings():
    conn = db()
    if request.method == "POST":
        slot_id = request.form.get("slot_id", type=int)
        slot = conn.execute("SELECT id, package_id, capacity, booked FROM slots WHERE id = ?",
                            (slot_id,)).fetchone()
        if slot is None:
            result = "invalid_slot"
        elif conn.execute("SELECT 1 FROM bookings WHERE username = ? AND slot_id = ?",
                          (session["username"], slot_id)).fetchone():
            result = "duplicate"
        elif slot["booked"] >= slot["capacity"]:
            result = "full"
        else:
            conn.execute("UPDATE slots SET booked = booked + 1 WHERE id = ?", (slot_id,))
            conn.execute("INSERT INTO bookings (username, slot_id, created_at) VALUES (?, ?, ?)",
                         (session["username"], slot_id, int(time.time())))
            conn.commit()
            result = "booked"
        audit("booking_attempt", slot_id=slot_id, package_id=slot["package_id"] if slot else "-",
              result=result)
        flash(f"Slot {slot_id}: {result.replace('_', ' ')}.", "info" if result == "booked" else "error")
        return redirect(url_for("bookings"))
    slots = conn.execute(
        "SELECT s.id, s.slot_date, s.capacity, s.booked, p.name AS package, p.price "
        "FROM slots s JOIN packages p ON p.id = s.package_id ORDER BY s.slot_date, s.id").fetchall()
    mine = conn.execute(
        "SELECT b.slot_id, s.slot_date, p.name AS package FROM bookings b "
        "JOIN slots s ON s.id = b.slot_id JOIN packages p ON p.id = s.package_id "
        "WHERE b.username = ? ORDER BY b.id DESC", (session["username"],)).fetchall()
    return render_template("bookings.html", slots=slots, mine=mine)


def _may_view(rec):
    role = session.get("role")
    if role in ("staff", "admin"):
        return True
    if role == "agency":
        return rec["agency_code"] == session.get("agency")
    if role == "pilgrim":
        return rec["account"] == session.get("username")
    return False


@app.route("/records")
@login_required("pilgrim", "agency", "staff", "admin")
def records():
    page = max(request.args.get("page", 1, type=int), 1)
    role = session["role"]
    base = "SELECT id, pilgrim_ref, full_name, nationality, agency_code, permit_status FROM pilgrims"
    if role in ("staff", "admin"):
        rows = db().execute(base + " ORDER BY id LIMIT 25 OFFSET ?", ((page - 1) * 25,)).fetchall()
    elif role == "agency":
        rows = db().execute(base + " WHERE agency_code = ? ORDER BY id LIMIT 25 OFFSET ?",
                            (session.get("agency"), (page - 1) * 25)).fetchall()
    else:
        rows = db().execute(base + " WHERE account = ?", (session["username"],)).fetchall()
    return render_template("records.html", rows=rows, page=page)


@app.route("/records/<int:pid>")
@login_required("pilgrim", "agency", "staff", "admin")
def record(pid):
    rec = db().execute("SELECT * FROM pilgrims WHERE id = ?", (pid,)).fetchone()
    if rec is None:
        audit("record_view", pilgrim_id=pid, result="not_found")
        abort(404)
    if not _may_view(rec):
        audit("record_view", pilgrim_id=pid, record_agency=rec["agency_code"], result="denied")
        abort(403)
    audit("record_view", pilgrim_id=pid, record_agency=rec["agency_code"], result="allowed")
    return render_template("record.html", rec=rec)


@app.route("/permits")
def permits():
    q = request.args.get("q", "").strip()
    rows = []
    if q:
        term = q[:100]
        rows = db().execute(
            "SELECT permit_no, holder_name, status, campaign FROM permits "
            "WHERE permit_no = ? OR (length(?) >= 4 AND holder_name LIKE ?) ORDER BY permit_no LIMIT 10",
            (term, term, f"%{term}%")).fetchall()
        audit("permit_search", q=q, rows=len(rows))
    return render_template("permits.html", q=q, rows=rows)


_MAGIC = {"jpg": b"\xff\xd8\xff", "jpeg": b"\xff\xd8\xff", "png": b"\x89PNG\r\n\x1a\n", "pdf": b"%PDF-"}


@app.route("/documents", methods=["GET", "POST"])
@login_required("pilgrim", "agency")
def documents():
    if request.method == "POST":
        upload = request.files.get("document")
        name = os.path.basename((upload.filename if upload else "") or "")[:120]
        ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
        head = upload.stream.read(8) if upload else b""
        if upload:
            upload.stream.seek(0)
        if ext not in _MAGIC or not head.startswith(_MAGIC[ext]):
            audit("doc_upload", filename=name or "-", ext=ext or "-", result="rejected",
                  reason="type_not_allowed")
            flash("Only JPG, PNG or PDF scans are accepted.", "error")
            return redirect(url_for("documents"))
        stored = f"{uuid.uuid4().hex}.{ext}"
        path = os.path.join(DOCS_DIR, stored)
        upload.save(path)
        audit("doc_upload", filename=name, ext=ext, size=os.path.getsize(path), stored_as=stored,
              result="accepted")
        flash("Document received. Thank you.", "info")
        return redirect(url_for("documents"))
    return render_template("documents.html")


@app.route("/pricing", methods=["GET", "POST"])
@login_required("staff", "admin")
def pricing():
    conn = db()
    if request.method == "POST":
        package_id = request.form.get("package_id", "")
        booking_ref = request.form.get("booking_ref", "").strip()[:20] or "-"
        reason = request.form.get("reason_code", "OTHER")[:20]
        new_price = request.form.get("new_price", type=int)
        row = conn.execute("SELECT price FROM packages WHERE id = ?", (package_id,)).fetchone()
        if row is None or new_price is None or not 0 <= new_price <= row["price"]:
            flash("Choose a package and a price between 0 and the list price.", "error")
            return redirect(url_for("pricing"))
        list_price = row["price"]
        discount = round((list_price - new_price) * 100 / list_price)
        conn.execute(
            "INSERT INTO price_overrides (username, package_id, booking_ref, list_price, new_price, "
            "reason_code, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (session["username"], package_id, booking_ref, list_price, new_price, reason, int(time.time())))
        conn.commit()
        audit("price_override", package_id=package_id, list_price=list_price, new_price=new_price,
              discount_pct=discount, reason_code=reason, booking_ref=booking_ref)
        flash(f"Override saved: {package_id} for {new_price:,} SAR ({discount}% off).", "info")
        return redirect(url_for("pricing"))
    packages = conn.execute("SELECT id, name, price FROM packages ORDER BY price").fetchall()
    recent = conn.execute("SELECT * FROM price_overrides ORDER BY id DESC LIMIT 10").fetchall()
    return render_template("pricing.html", packages=packages, recent=recent)


@app.route("/export")
@login_required("agency", "staff", "admin")
def export_page():
    return render_template("export.html")


@app.route("/export.csv")
@login_required("agency", "staff", "admin")
def export_csv():
    cols = "pilgrim_ref, full_name, nationality, passport_no, phone, agency_code, permit_status"
    if session["role"] == "agency":
        rows = db().execute(f"SELECT {cols} FROM pilgrims WHERE agency_code = ? ORDER BY id",
                            (session.get("agency"),)).fetchall()
        scope = "own"
    else:
        rows = db().execute(f"SELECT {cols} FROM pilgrims ORDER BY id").fetchall()
        scope = "all"
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([c.strip() for c in cols.split(",")])
    writer.writerows([tuple(r) for r in rows])
    audit("data_export", record_count=len(rows), scope=scope, export_format="csv")
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=pilgrims.csv"})


@app.errorhandler(403)
def forbidden(_e):
    return render_template("error.html", code=403, message="You do not have access to this page."), 403


@app.errorhandler(404)
def not_found(_e):
    return render_template("error.html", code=404, message="Page not found."), 404


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000)
