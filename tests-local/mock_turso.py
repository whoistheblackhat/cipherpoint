"""
Mock Turso libSQL HTTP server for LOCAL TESTING ONLY.

Implements just enough of the POST /v2/pipeline protocol (execute / begin /
commit / rollback steps + baton-based interactive transactions) to run the
CipherPoint backend against a plain local SQLite file, so end-to-end tests
never touch the production database.

Per-connection locking + WAL mode: an open transaction on one connection
must not stop another connection's COMMIT from reaching SQLite, otherwise
blocked writers deadlock until their busy timeout — exactly what happens on
a real Turso server, so the mock emulates it fairly.

Run:  python3 mock_turso.py [port] [sqlite_path]
"""
import json
import sqlite3
import sys
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 9800
DB_PATH = sys.argv[2] if len(sys.argv) > 2 else "/tmp/mock_turso_test.db"

_batons: dict = {}      # baton_id -> sqlite3 connection with (maybe) open txn
_conn_locks: dict = {}  # id(conn) -> threading.Lock


def _lock_for(conn) -> threading.Lock:
    lock = _conn_locks.get(id(conn))
    if lock is None:
        lock = threading.Lock()
        _conn_locks[id(conn)] = lock
    return lock


def _base_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, isolation_level=None)
    conn.execute("PRAGMA foreign_keys = OFF")
    conn.execute("PRAGMA busy_timeout = 30000")
    try:
        conn.execute("PRAGMA journal_mode = WAL")
    except sqlite3.Error:
        pass
    return conn


_autocommit_conn = _base_conn()


def _val_out(v):
    if v is None:
        return {"type": "null"}
    if isinstance(v, int):
        return {"type": "integer", "value": str(v)}
    if isinstance(v, float):
        return {"type": "float", "value": repr(v)}
    if isinstance(v, bytes):
        return {"type": "blob", "value": v.hex()}
    return {"type": "text", "value": str(v)}


def _run_execute(conn, sql):
    try:
        cur = conn.execute(sql)
    except sqlite3.Error as e:
        return {"type": "execute", "error": {"message": str(e)}}

    cols = []
    try:
        cols = cur.description or []
    except Exception:
        cols = []
    rows = []
    affected = 0
    last_rowid = None
    if cols:
        for raw in cur.fetchall():
            rows.append([_val_out(v) for v in raw])
        col_meta = [{"name": (c[0] or ""), "decltype": c[1] or ""} for c in cols]
    else:
        col_meta = []
        affected = max(0, cur.rowcount if cur.rowcount is not None else 0)
        try:
            last_rowid = cur.lastrowid
        except Exception:
            last_rowid = None
    body = {
        "cols": col_meta,
        "rows": rows,
        "affected_row_count": affected,
    }
    if last_rowid is not None:
        body["last_insert_rowid"] = last_rowid
    # Real Turso nests the inner response as {"type": "execute", "result": ...}
    return {"type": "execute", "response": {"type": "execute", "result": body}}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # keep test output clean

    def do_POST(self):
        if not self.path.startswith("/v2/pipeline"):
            self.send_response(404)
            self.end_headers()
            return
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length) or b"{}")
        steps = body.get("requests", [])
        baton = body.get("baton")

        conn = None
        baton_out = None
        if baton:
            conn = _batons.get(baton)
            if conn is None:
                self._respond({"results": [{"type": "error", "error": {"message": "Unknown baton"}}]})
                return
            baton_out = baton
        else:
            conn = _autocommit_conn

        results = []
        for step in steps:
            stype = step.get("type")
            # Per-connection locking: an open transaction on connection A
            # must NOT prevent connection B's COMMIT from reaching SQLite.
            with _lock_for(conn):
                if stype == "execute":
                    sql = (step.get("stmt") or {}).get("sql", "")
                    results.append(_run_execute(conn, sql))
                elif stype == "begin":
                    if baton_out is None:
                        baton_out = str(uuid.uuid4())
                        conn = _base_conn()
                        _batons[baton_out] = conn
                    try:
                        conn.execute("BEGIN")
                        results.append({"type": "begin", "response": {}})
                    except sqlite3.Error as e:
                        results.append({"type": "begin", "error": {"message": str(e)}})
                elif stype == "commit":
                    try:
                        conn.execute("COMMIT")
                        results.append({"type": "commit", "response": {}})
                    except sqlite3.Error as e:
                        results.append({"type": "commit", "error": {"message": str(e)}})
                elif stype == "rollback":
                    try:
                        conn.execute("ROLLBACK")
                        results.append({"type": "rollback", "response": {}})
                    except sqlite3.Error as e:
                        results.append({"type": "rollback", "error": {"message": str(e)}})
                else:
                    results.append({"type": str(stype), "error": {"message": f"unsupported step {stype}"}})

        self._respond({"baton": baton_out, "results": results})

    def _respond(self, payload):
        data = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


if __name__ == "__main__":
    server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"mock turso on 127.0.0.1:{PORT} -> {DB_PATH}")
    server.serve_forever()
