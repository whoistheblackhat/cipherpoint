"""
CipherPoint end-to-end tests — PHASE A (auth + economy).
Run against a LOCAL app instance backed by mock_turso.py (no production).

Usage:  python3 e2e_phase_a.py
Setup:  1) python3 tests-local/mock_turso.py 9800 /tmp/cp_test.db
        2) uvicorn main:app on 127.0.0.1:8001 (see run_tests.sh)
"""
import concurrent.futures as cf
import os
import sys

import requests

BASE = os.environ.get("CP_BASE", "http://127.0.0.1:8001")
PASS, FAIL = [], []


def check(name, cond, extra=""):
    (PASS if cond else FAIL).append((name, extra))
    print(("  OK " if cond else "  FAIL ") + name + (f"  [{extra}]" if extra and not cond else ""))


def auth(t):
    return {"Authorization": f"Bearer {t}"}


def me(t):
    return requests.get(f"{BASE}/api/auth/me", headers=auth(t), timeout=20)


sfx = os.getpid() % 10000
alice, bob = f"alice{sfx}", f"bob{sfx}"

print("== A1. Signup / login ==")
r = requests.post(f"{BASE}/api/auth/signup", json={"username": alice, "email": f"{alice}@t.dev", "password": "Hunter2Password1"}, timeout=20)
check("signup alice", r.status_code in (200, 201), r.text[:150])
j = r.json()
alice_tok, alice_rt = j.get("access_token"), j.get("refresh_token")
check("signup returns access+refresh (FIXED)", bool(alice_tok and alice_rt), r.text[:200])
r = requests.post(f"{BASE}/api/auth/signup", json={"username": bob, "email": f"{bob}@t.dev", "password": "Hunter2Password1"}, timeout=20)
bob_tok, bob_rt = r.json().get("access_token"), r.json().get("refresh_token")
r = requests.post(f"{BASE}/api/auth/signup", json={"username": alice + "_x", "email": f"{alice}@t.dev", "password": "Hunter2Password1"}, timeout=20)
check("duplicate email rejected", r.status_code == 400, str(r.status_code))
r = requests.post(f"{BASE}/api/auth/signup", json={"username": "ab", "email": "ab@t.dev", "password": "Hunter2Password1"}, timeout=20)
check("short username rejected", r.status_code == 400)
r = requests.post(f"{BASE}/api/auth/signup", json={"username": "longpw", "email": "lp@t.dev", "password": "Aa1" + "x" * 90}, timeout=20)
check("password >72 bytes rejected (bcrypt5)", r.status_code == 400, r.text[:120])
r = requests.post(f"{BASE}/api/auth/login", json={"username": alice, "password": "Hunter2Password1"}, timeout=20)
check("login ok", r.status_code == 200)
check("login has no flagged_for_review", "flagged_for_review" not in r.json())
check("wrong password 401", requests.post(f"{BASE}/api/auth/login", json={"username": alice, "password": "nope"}, timeout=20).status_code == 401)

print("== A2. Refresh token is not an access token (H1) ==")
check("refresh as Bearer -> 401", me(alice_rt).status_code == 401, str(me(alice_rt).status_code))
check("access works on /me", me(alice_tok).status_code == 200)

print("== A3. Refresh rotation + replay rejection ==")
r = requests.post(f"{BASE}/api/auth/refresh", json={"refresh_token": alice_rt}, timeout=20)
check("refresh rotates", r.status_code == 200, r.text[:150])
at2, rt2 = r.json().get("access_token"), r.json().get("refresh_token")
check("new pair returned", bool(at2 and rt2))
check("old refresh replay 401", requests.post(f"{BASE}/api/auth/refresh", json={"refresh_token": alice_rt}, timeout=20).status_code == 401)

print("== A4. Logout revokes access + refresh ==")
r = requests.post(f"{BASE}/api/auth/logout", headers={**auth(bob_tok), "Content-Type": "application/json"}, json={"refresh_token": bob_rt}, timeout=20)
check("logout ok + refresh revoked", r.status_code == 200 and r.json().get("refresh_revoked") is True, r.text[:150])
check("access dead after logout", me(bob_tok).status_code == 401)
check("refresh dead after logout", requests.post(f"{BASE}/api/auth/refresh", json={"refresh_token": bob_rt}, timeout=20).status_code == 401)

print("== A5. Admin authz + flag secrecy ==")
r = requests.post(f"{BASE}/api/auth/login", json={"username": "admin", "password": "LocalTestAdmin123"}, timeout=20)
admin_tok = r.json()["access_token"]
check("admin login", r.status_code == 200)
check("non-admin blocked from admin route", requests.get(f"{BASE}/api/admin/users", headers=auth(alice_tok), timeout=20).status_code in (401, 403))
r = requests.post(f"{BASE}/api/challenges/create", headers=auth(admin_tok), json={
    "title": "Hidden Metadata in a Tokyo Street Photo", "category": "OSINT", "difficulty": "Easy",
    "description": "Find the flag.", "telegram_file_id": "AgACAgIAAxkBAAIBEGdabc123xyz012345",
    "correct_flag": "CP{test_flag_2026}", "points_reward": 100,
    "hint_1": "hint one", "hint_1_cost": 10, "hint_2": "hint two", "hint_2_cost": 20}, timeout=20)
check("admin creates challenge (500 FIXED)", r.status_code in (200, 201), r.text[:200])
cid = r.json().get("id")
check("challenge id returned", bool(cid), r.text[:200])
check("flag not leaked in listing", "CP{test_flag_2026}" not in requests.get(f"{BASE}/api/challenges", timeout=20).text)

print("== A6. Solve + concurrent double-solve race ==")
r = requests.post(f"{BASE}/api/challenges/submit", headers=auth(alice_tok), json={"challenge_id": cid, "flag": "wrong"}, timeout=20)
check("wrong flag rejected", r.status_code == 200 and r.json().get("success") is False, r.text[:150])
coins_before = me(alice_tok).json().get("coins") or 0


def sub(_):
    return requests.post(f"{BASE}/api/challenges/submit", headers=auth(alice_tok),
                         json={"challenge_id": cid, "flag": "cp{TEST_flag_2026}"}, timeout=60)


with cf.ThreadPoolExecutor(10) as ex:
    results = list(ex.map(sub, range(10)))
wins = [x for x in results if x.status_code == 200 and x.json().get("success")]
check("race: exactly 1 of 10 wins", len(wins) == 1, f"{len(wins)} wins; statuses: {[x.status_code for x in results]}")
coins_after = me(alice_tok).json().get("coins") or 0
check("coins +100 exactly once", coins_after == coins_before + 100, f"{coins_before}->{coins_after}")
lb = requests.get(f"{BASE}/api/leaderboard", timeout=20).json()
lbm = {u.get("username"): u for u in lb}
check("leaderboard single award", lbm.get(alice, {}).get("rank_points") == 100, str(lbm.get(alice)))

print("== A7. Hint unlock: claim-first, single charge ==")
r = requests.post(f"{BASE}/api/hints/unlock", headers=auth(alice_tok), json={"challenge_id": cid, "hint_number": 1}, timeout=20)
check("hint unlock ok", r.status_code == 200, r.text[:150])
c1 = r.json().get("remaining_coins")
r = requests.post(f"{BASE}/api/hints/unlock", headers=auth(alice_tok), json={"challenge_id": cid, "hint_number": 1}, timeout=20)
check("second = already unlocked", r.json().get("message") == "Hint already unlocked", r.text[:150])
check("no double charge", r.json().get("remaining_coins") == c1, f"{c1}->{r.json().get('remaining_coins')}")

print("== A8. Daily bonus single claim ==")
r1 = requests.post(f"{BASE}/api/profile/daily-bonus", headers=auth(alice_tok), timeout=20)
r2 = requests.post(f"{BASE}/api/profile/daily-bonus", headers=auth(alice_tok), timeout=20)
check("first 200", r1.status_code == 200, r1.text[:120])
check("second 409", r2.status_code == 409, str(r2.status_code))

print("== A9. Rate-limit sweeper smoke ==")
ok = all(requests.get(f"{BASE}/api/leaderboard?limit={50 + i}", timeout=20).status_code == 200 for i in range(6))
check("sweeper no errors", ok)

print(f"\nRESULT A: PASS={len(PASS)} FAIL={len(FAIL)}")
for n, e in FAIL:
    print(f"  FAILED: {n} {e}")
sys.exit(1 if FAIL else 0)
