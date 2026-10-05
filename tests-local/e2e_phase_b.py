"""
CipherPoint end-to-end tests — PHASE B (fingerprint, bans, honeypot).
Run AFTER phase A (fresh app restart clears per-IP signup buckets).

Usage:  python3 e2e_phase_b.py
"""
import hashlib
import os
import sqlite3
import sys

import requests

BASE = os.environ.get("CP_BASE", "http://127.0.0.1:8001")
DB_PATH = os.environ.get("CP_DB", "/tmp/cp_test.db")
PASS, FAIL = [], []


def check(name, cond, extra=""):
    (PASS if cond else FAIL).append((name, extra))
    print(("  OK " if cond else "  FAIL ") + name + (f"  [{extra}]" if extra and not cond else ""))


def auth(t):
    return {"Authorization": f"Bearer {t}"}


sfx = os.getpid() % 10000

print("== B1. Fingerprint hashed at rest ==")
raw_fp = "device-fingerprint-abc-123"
r = requests.post(f"{BASE}/api/auth/signup",
                  json={"username": f"fpu{sfx}", "email": f"fpu{sfx}@t.dev", "password": "Hunter2Password1", "fingerprint": raw_fp},
                  timeout=20)
check("signup with fp ok", r.status_code in (200, 201), r.text[:150])
db = sqlite3.connect(DB_PATH)
row = db.execute("SELECT device_fingerprint_hash FROM users WHERE username=?", (f"fpu{sfx}",)).fetchone()
check("fingerprint stored as sha256", bool(row) and row[0] == hashlib.sha256(raw_fp.encode()).hexdigest(), str(row))

print("== B2. Ban path revokes sessions instantly ==")
carol = f"carol{sfx}"
r = requests.post(f"{BASE}/api/auth/signup", json={"username": carol, "email": f"{carol}@t.dev", "password": "Hunter2Password1"}, timeout=20)
carol_tok = r.json()["access_token"]
r = requests.post(f"{BASE}/api/auth/login", json={"username": "admin", "password": "LocalTestAdmin123"}, timeout=20)
admin_tok = r.json()["access_token"]
users = requests.get(f"{BASE}/api/admin/users", headers=auth(admin_tok), timeout=20).json()
users = users if isinstance(users, list) else users.get("items", [])
carol_id = next(u["id"] for u in users if u["username"] == carol)
r = requests.post(f"{BASE}/api/admin/users/ban", headers=auth(admin_tok), json={"user_id": carol_id, "reason": "e2e ban"}, timeout=20)
check("admin ban ok", r.status_code == 200, r.text[:150])
check("banned user token revoked instantly", requests.get(f"{BASE}/api/auth/me", headers=auth(carol_tok), timeout=20).status_code == 401)
check("banned user cannot re-login", requests.post(f"{BASE}/api/auth/login", json={"username": carol, "password": "Hunter2Password1"}, timeout=20).status_code == 403)

print("== B3. Banned user cannot delete own account ==")
dave = f"dave{sfx}"
r = requests.post(f"{BASE}/api/auth/signup", json={"username": dave, "email": f"{dave}@t.dev", "password": "Hunter2Password1"}, timeout=20)
dave_tok = r.json()["access_token"]
users = requests.get(f"{BASE}/api/admin/users", headers=auth(admin_tok), timeout=20).json()
users = users if isinstance(users, list) else users.get("items", [])
dave_id = next(u["id"] for u in users if u["username"] == dave)
requests.post(f"{BASE}/api/admin/users/ban", headers=auth(admin_tok), json={"user_id": dave_id, "reason": "del test"}, timeout=20)
r = requests.delete(f"{BASE}/api/settings/account", headers=auth(dave_tok), timeout=20)
# 401 is also correct: the ban revokes the token first, so the request
# never even reaches the endpoint's own ban guard (403). Both = refused.
check("banned user cannot delete account (401/403)", r.status_code in (401, 403), str(r.status_code))

print("== B4. Honeypot trips site-wide throttle (runs last) ==")
h = requests.get(f"{BASE}/.env", timeout=20)
check("honeypot returns decoy 404", h.status_code == 404, str(h.status_code))
h2 = requests.get(f"{BASE}/api/health", timeout=20)
check("after honeypot, IP throttled 429", h2.status_code == 429, str(h2.status_code))

print(f"\nRESULT B: PASS={len(PASS)} FAIL={len(FAIL)}")
for n, e in FAIL:
    print(f"  FAILED: {n} {e}")
sys.exit(1 if FAIL else 0)
