"""
Turso/libSQL adapter using HTTP API and the `requests` library.

Provides a thin DB-API 2.0 compatible wrapper so SQLAlchemy can treat
Turso as just another SQLite dialect via the 'sqlite+pyturso' URL scheme.

For SQLAlchemy core/ORM usage we set up:
- dialect = sqlite
- creator = lambda: pyturbo_connection()
"""

import os
import json
import time
import threading
import requests
from typing import Any, Iterable, List, Optional, Tuple


class TursoError(Exception):
    pass


class TursoConnection:
    """Minimal DB-API 2.0 connection wrapper for Turso HTTP pipeline API."""

    paramstyle = "qmark"
    autocommit = False

    def __init__(self, url: str, token: str):
        self.url = url.rstrip("/")
        self.token = token
        self._closed = False
        self._lock = threading.Lock()

    def _pipeline(self, requests_body: List[dict]) -> dict:
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }
        payload = {"requests": requests_body}
        for attempt in range(3):
            try:
                resp = requests.post(
                    f"{self.url}/v2/pipeline",
                    json=payload,
                    headers=headers,
                    timeout=15,
                )
                if resp.status_code >= 500:
                    time.sleep(0.5 * (attempt + 1))
                    continue
                if resp.status_code == 401:
                    raise TursoError("Turso auth failed (401). Check TURSO_AUTH_TOKEN.")
                if resp.status_code >= 400:
                    raise TursoError(f"Turso API error {resp.status_code}: {resp.text[:500]}")
                return resp.json()
            except requests.RequestException as e:
                if attempt == 2:
                    raise TursoError(f"Turso HTTP failure: {e}")
                time.sleep(0.5 * (attempt + 1))
        raise TursoError("Turso pipeline failed after retries")

    def _convert_value(self, v: Any, decltype: str = None) -> Any:
        if v is None:
            return None
        if isinstance(v, dict) and "type" in v:
            t = v["type"]
            if t == "null":
                return None
            val = v.get("value")
            if val is None:
                return None
            if t == "integer":
                return int(val)
            if t == "float":
                return float(val)
            if t == "text":
                if decltype and decltype.upper() in ("DATETIME", "TIMESTAMP") and isinstance(val, str):
                    try:
                        from datetime import datetime
                        iso = val.replace(" ", "T", 1) if " " in val else val
                        return datetime.fromisoformat(iso).isoformat()
                    except Exception:
                        return val
                if decltype and decltype.upper() == "DATE" and isinstance(val, str):
                    try:
                        from datetime import date
                        return date.fromisoformat(val[:10]).isoformat()
                    except Exception:
                        return val
                return val
            if t == "blob":
                return val
        return v

    def _normalize_rows(self, result: dict) -> Tuple[List[str], List[Tuple], int]:
        if result.get("type") != "execute":
            raise TursoError(f"Unexpected Turso response type: {result.get('type')}")
        body = result.get("result", {})
        cols_meta = body.get("cols", [])
        cols = [c["name"] for c in cols_meta]
        rows_raw = body.get("rows", [])
        rows = [
            tuple(self._convert_value(c, cols_meta[i].get("decltype")) for i, c in enumerate(r))
            for r in rows_raw
        ]
        affected = body.get("affected_row_count", 0) or 0
        return cols, rows, affected

    @staticmethod
    def _extract_result(response: dict) -> dict:
        """Return the statement response or raise the server-side SQL error."""
        results = response.get("results")
        if not isinstance(results, list) or not results:
            raise TursoError(f"Invalid Turso pipeline response: {response}")

        item = results[0] or {}
        result = item.get("response")
        if isinstance(result, dict):
            return result

        error = item.get("error") or response.get("error")
        if isinstance(error, dict):
            message = error.get("message") or error.get("code") or str(error)
        else:
            message = str(error or item)
        raise TursoError(f"Turso statement failed: {message}")

    def cursor(self):
        return TursoCursor(self)

    def commit(self):
        pass

    def rollback(self):
        pass

    def close(self):
        self._closed = True

    def execute(self, sql: str, params: Optional[Iterable] = None):
        cursor = self.cursor()
        cursor.execute(sql, params)
        return cursor

    # SQLite-specific shims required by SQLAlchemy dialect
    def create_function(self, name, num_params, func, deterministic=False):
        pass

    def create_aggregate(self, name, num_params, aggregate_class):
        pass

    def create_collation(self, name, func):
        pass

    def enable_load_extension(self, enabled):
        pass

    def load_extension(self, path):
        pass

    def set_authorizer(self, authorizer_callback):
        pass

    def set_progress_handler(self, handler, n_instructions):
        pass

    def set_trace_callback(self, trace_callback):
        pass

    def getlimit(self, category):
        return 0

    def setlimit(self, category, limit):
        pass

    def get_autocommit(self):
        return self.autocommit

    def serialize(self, **kwargs):
        return b""

    def deserialize(self, data, **kwargs):
        pass

    def iterdump(self):
        return iter([])

    def backup(self, target, **kwargs):
        pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


class TursoCursor:
    def __init__(self, conn: TursoConnection):
        self.conn = conn
        self._rows: List[Tuple] = []
        self._cols: List[str] = []
        self._idx = 0
        self._affected = 0
        self._last_sql = ""
        self._last_params: Optional[List] = None
        self.description: List[Tuple] = []

    @staticmethod
    def _bind(sql: str, params: Optional[Iterable]) -> Tuple[str, List]:
        if not params:
            return sql, []
        params = list(params)
        out_sql = []
        idx = 0
        param_idx = 0
        in_string = False
        in_identifier = False
        while idx < len(sql):
            ch = sql[idx]
            nxt = sql[idx + 1] if idx + 1 < len(sql) else ""

            if ch == "'" and not in_identifier and (idx == 0 or sql[idx - 1] != "\\"):
                if in_string and nxt == "'":
                    out_sql.append("''")
                    idx += 2
                    continue
                in_string = not in_string
            elif ch == '"' and not in_string:
                in_identifier = not in_identifier

            if ch == "?" and not in_string and not in_identifier:
                out_sql.append(TursoCursor._format_param(params[param_idx]))
                param_idx += 1
                idx += 1
                continue
            out_sql.append(ch)
            idx += 1
        if param_idx != len(params):
            raise TursoError(f"Param count mismatch: {param_idx} placeholders, {len(params)} params")
        return "".join(out_sql), []

    @staticmethod
    def _format_param(v: Any) -> str:
        if v is None:
            return "NULL"
        if isinstance(v, bool):
            return "1" if v else "0"
        if isinstance(v, (int, float)):
            return str(v)
        s = str(v).replace("'", "''")
        return f"'{s}'"

    def execute(self, sql: str, params: Optional[Iterable] = None):
        self._last_sql = sql
        sql_text, _ = self._bind(sql, params)
        stripped = sql_text.lstrip().lower()
        is_query = (
            stripped.startswith(("select", "pragma"))
            or stripped.startswith("with ")
            or " returning " in stripped
        )

        with self.conn._lock:
            response = self.conn._pipeline([{"type": "execute", "stmt": {"sql": sql_text}}])
            result = self.conn._extract_result(response)
            body = result.get("result", {}) or {}

            if is_query:
                cols, rows, _ = self.conn._normalize_rows(result)
                self._cols = cols
                self.description = [(c, None, None, None, None, None, None) for c in cols]
                self._rows = rows
                self._affected = 0
            else:
                self._cols = []
                self.description = []
                self._rows = []
                affected = body.get("affected_row_count", 0) or 0
                self._affected = affected
            last_id = body.get("last_insert_rowid")
            self._lastrowid = int(last_id) if last_id not in (None, "") else None
        self._idx = 0
        return self

    @property
    def lastrowid(self):
        """SQLAlchemy reads cursor.lastrowid after INSERT to determine PK."""
        return getattr(self, "_lastrowid", None)

    def executemany(self, sql: str, seq_of_params: Iterable[Iterable]):
        params_list = list(seq_of_params)
        with self.conn._lock:
            for params in params_list:
                sql_text, _ = self._bind(sql, params)
                self.conn._pipeline([{"type": "execute", "stmt": {"sql": sql_text}}])
        self._affected = len(params_list)
        return self

    def fetchone(self):
        if self._idx >= len(self._rows):
            return None
        row = self._rows[self._idx]
        self._idx += 1
        return row

    def fetchall(self):
        remaining = self._rows[self._idx:]
        self._idx = len(self._rows)
        return remaining

    def fetchmany(self, size=None):
        if size is None:
            size = 1
        result = self._rows[self._idx:self._idx + size]
        self._idx += len(result)
        return result

    @property
    def rowcount(self):
        return self._affected

    def close(self):
        pass


def connect_turso(url: str, token: str) -> TursoConnection:
    if url.startswith("libsql://"):
        url = "https://" + url[len("libsql://"):]
    return TursoConnection(url, token)


def is_turso_configured() -> bool:
    return bool(os.getenv("TURSO_URL")) and bool(os.getenv("TURSO_AUTH_TOKEN"))