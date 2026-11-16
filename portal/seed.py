#!/usr/bin/env python3
"""Create the portal database with synthetic lab data (no real people).

Accounts (lab passwords, change them if the VM is ever reachable from outside the lab):
  pilgrim0001 .. pilgrim0300   role pilgrim   password Pilgrim#2026
  agency.in01 / pk01 / id01 / eg01 / ng01 / sa01      role agency   password Agency#2026
  staff.ops01 / ops02 / ops03 / staff.visa01 / staff.reporting   role staff   password Staff#2026
  fin.approver01 / fin.approver02                      role staff   password Finance#2026
  portal.admin                                         role admin   password Admin#2026
"""
import os
import random
import sqlite3
import sys

from werkzeug.security import generate_password_hash

DB_PATH = os.environ.get("PORTAL_DB", os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "portal.db"))

SCHEMA = """
CREATE TABLE users (username TEXT PRIMARY KEY, password_hash TEXT, role TEXT, full_name TEXT,
                    agency_code TEXT, active INTEGER DEFAULT 1);
CREATE TABLE packages (id TEXT PRIMARY KEY, name TEXT, price INTEGER);
CREATE TABLE slots (id INTEGER PRIMARY KEY, package_id TEXT, slot_date TEXT, capacity INTEGER, booked INTEGER DEFAULT 0);
CREATE TABLE bookings (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, slot_id INTEGER, created_at INTEGER);
CREATE TABLE pilgrims (id INTEGER PRIMARY KEY, pilgrim_ref TEXT, full_name TEXT, nationality TEXT,
                       passport_no TEXT, phone TEXT, agency_code TEXT, permit_status TEXT, account TEXT);
CREATE TABLE permits (permit_no TEXT PRIMARY KEY, pilgrim_id INTEGER, holder_name TEXT, status TEXT, campaign TEXT);
CREATE TABLE price_overrides (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, package_id TEXT,
                              booking_ref TEXT, list_price INTEGER, new_price INTEGER, reason_code TEXT, created_at INTEGER);
"""

# Agencies and how many pilgrims each brings (India has by far the largest quota).
AGENCIES = [("AG-IN01", "IN", 1200), ("AG-PK01", "PK", 300), ("AG-ID01", "ID", 350),
            ("AG-EG01", "EG", 150), ("AG-NG01", "NG", 120), ("AG-SA01", "SA", 180)]
FIRST = {"IN": ["Mohammed", "Abdul", "Ayesha", "Imran", "Fatima", "Salman", "Zainab", "Arif"],
         "PK": ["Ahmed", "Bilal", "Hira", "Usman", "Sana", "Hamza", "Maryam", "Faisal"],
         "ID": ["Muhammad", "Siti", "Agus", "Nur", "Rizky", "Dewi", "Budi", "Aisyah"],
         "EG": ["Mahmoud", "Mona", "Karim", "Heba", "Omar", "Nadia", "Tarek", "Yasmin"],
         "NG": ["Abubakar", "Aisha", "Musa", "Hauwa", "Ibrahim", "Zainab", "Sani", "Halima"],
         "SA": ["Abdullah", "Noura", "Fahad", "Reem", "Khalid", "Lama", "Saud", "Haya"]}
LAST = {"IN": ["Khan", "Ansari", "Qureshi", "Shaikh", "Siddiqui"], "PK": ["Malik", "Butt", "Chaudhry", "Raza", "Akhtar"],
        "ID": ["Santoso", "Wijaya", "Hidayat", "Saputra", "Rahman"], "EG": ["Hassan", "Mostafa", "Fawzy", "Saleh", "Gaber"],
        "NG": ["Bello", "Abubakar", "Yusuf", "Lawal", "Sani"], "SA": ["Alqahtani", "Alharbi", "Alotaibi", "Alshehri", "Alghamdi"]}
DIAL = {"IN": "+91", "PK": "+92", "ID": "+62", "EG": "+20", "NG": "+234", "SA": "+966"}
PACKAGES = [("UMR-1448", "Umrah - 10 days", 3800), ("ECO-1448", "Hajj Economy", 12500),
            ("STD-1448", "Hajj Standard", 18900), ("PRM-1448", "Hajj Premium", 28000),
            ("VIP-1448", "Hajj VIP (Mina towers)", 45000)]


def main():
    if os.path.exists(DB_PATH) and "--force" not in sys.argv:
        print(f"{DB_PATH} exists; use --force to rebuild")
        return
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    rnd = random.Random(1448)
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(SCHEMA)
    conn.executemany("INSERT INTO packages VALUES (?, ?, ?)", PACKAGES)

    slot_id = 100
    for day in range(1, 21):
        for pkg in ("ECO-1448", "STD-1448"):
            slot_id += 1
            conn.execute("INSERT INTO slots (id, package_id, slot_date, capacity, booked) VALUES (?, ?, ?, ?, ?)",
                         (slot_id, pkg, f"1448-11-{day:02d} (arrival group)", rnd.choice([20, 40, 60]), rnd.randint(0, 15)))

    pid = 1000
    for code, cc, count in AGENCIES:
        for _ in range(count):
            pid += 1
            name = f"{rnd.choice(FIRST[cc])} {rnd.choice(LAST[cc])}"
            passport = f"{rnd.choice('PAKN')}{rnd.randint(1000000, 9999999)}"
            phone = f"{DIAL[cc]} {rnd.randint(100, 999)} {rnd.randint(1000000, 9999999)}"
            status = rnd.choice(["issued", "issued", "issued", "pending", "cancelled"])
            account = f"pilgrim{pid - 1000:04d}" if pid - 1000 <= 300 else None
            conn.execute("INSERT INTO pilgrims VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                         (pid, f"PLG-{pid}", name, cc, passport, phone, code, status, account))
            conn.execute("INSERT INTO permits VALUES (?, ?, ?, ?, ?)",
                         (f"HJ1448-{pid:07d}", pid, name, status, code))

    users = []
    h = {role: generate_password_hash(pw) for role, pw in
         [("pilgrim", "Pilgrim#2026"), ("agency", "Agency#2026"), ("staff", "Staff#2026"),
          ("finance", "Finance#2026"), ("admin", "Admin#2026")]}
    for i in range(1, 301):
        name = conn.execute("SELECT full_name FROM pilgrims WHERE account = ?", (f"pilgrim{i:04d}",)).fetchone()[0]
        users.append((f"pilgrim{i:04d}", h["pilgrim"], "pilgrim", name, None))
    for code, cc, _ in AGENCIES:
        users.append((f"agency.{cc.lower()}01", h["agency"], "agency", f"Licensed agency {code}", code))
    for u, n in [("staff.ops01", "Operations officer 1"), ("staff.ops02", "Operations officer 2"),
                 ("staff.ops03", "Operations officer 3"), ("staff.visa01", "Visa processing"),
                 ("staff.reporting", "Ministry reporting")]:
        users.append((u, h["staff"], "staff", n, None))
    users += [("fin.approver01", h["finance"], "staff", "Finance approver 1", None),
              ("fin.approver02", h["finance"], "staff", "Finance approver 2", None),
              ("portal.admin", h["admin"], "admin", "Portal administrator", None)]
    conn.executemany("INSERT INTO users (username, password_hash, role, full_name, agency_code) VALUES (?, ?, ?, ?, ?)", users)
    conn.commit()
    total = conn.execute("SELECT COUNT(*) FROM pilgrims").fetchone()[0]
    print(f"seeded {DB_PATH}: {total} pilgrims, {len(users)} accounts, {slot_id - 100} booking slots")


if __name__ == "__main__":
    main()
