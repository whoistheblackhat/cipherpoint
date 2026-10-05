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
        # Interactive-transaction handle returned by the Turso HTTP API.
        # None = no transaction open; every statement otherwise autocommits.
        self._baton: Optional[str] = None
        # If the server ever rejects BEGIN or a response is missing its
        # baton, we degrade to plain autocommit (the previous behavior)
        # instead of breaking every write.
        self._txn_ok = True

    def _pipeline(
        self,
        requests_body: List[dict],
        allow_retry: bool = True,
        baton: Optional[str] = None,
    ) -> dict:
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }
        payload: dict = {"requests": requests_body}
        if baton is not None:
            payload["baton"] = baton
        attempts = 3 if allow_retry else 1
        for attempt in range(attempts):
            try:
                resp = requests.post(
                    f"{self.url}/v2/pipeline",
                    json=payload,
                    headers=headers,
                    timeout=15,
                )
                if resp.status_code >= 500:
                    if attempt < attempts - 1:
                        time.sleep(0.5 * (attempt + 1))
                        continue
                    raise TursoError(f"Turso API error {resp.status_code}: {resp.text[:500]}")
                if resp.status_code == 401:
                    raise TursoError("Turso auth failed (401). Check TURSO_AUTH_TOKEN.")
                if resp.status_code >= 400:
                    raise TursoError(f"Turso API error {resp.status_code}: {resp.text[:500]}")
                return resp.json()
            except requests.RequestException as e:
                if attempt >= attempts - 1:
                    raise TursoError(f"Turso HTTP failure: {e}")
                time.sleep(0.5 * (attempt + 1))
        raise TursoError("Turso pipeline failed after retries")

    @staticmethod
    def _check_step_errors(response: dict) -> None:
        """Raise if ANY step in a multi-step pipeline returned an error."""
        results = response.get("results")
        if not isinstance(results, list):
            raise TursoError(f"Invalid Turso pipeline response: {response}")
        for item in results:
            item = item or {}
            error = item.get("error")
            if isinstance(error, dict):
                message = error.get("message") or error.get("code") or str(error)
            else:
                message = str(error) if error else None
            if message:
                raise TursoError(f"Turso statement failed: {message}")

    @staticmethod
    def _raise_statement_error(message: str):
        """Surface constraint violations as sqlite3.IntegrityError so
        SQLAlchemy maps them to IntegrityError — the app's
        `except IntegrityError` handlers (signup, hint unlock, flag submit)
        depend on that mapping to return friendly 4xx responses instead of
        unhandled 500s."""
        lowered = (message or "").lower()
        if "unique constraint" in lowered or "constraint failed" in lowered:
            import sqlite3 as _sqlite3
            raise _sqlite3.IntegrityError(message)
        raise TursoError(f"Turso statement failed: {message}")

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

    def _end_transaction(self, step: str) -> None:
        """Finish the open interactive transaction ('commit' or 'rollback').

        Always clears the baton, even if the network call fails — a stale
        baton must never be reused. Rollback errors are swallowed because
        this is often invoked while another exception is propagating.
        """
        baton, self._baton = self._baton, None
        if not baton or not self._txn_ok:
            return
        try:
            with self._lock:
                # Transactions are baton-bound sessions; finalize them with
                # plain SQL (the pipeline has no begin/commit step variants
                # on the current Turso Cloud API).
                response = self._pipeline(
                    [{"type": "execute", "stmt": {"sql": "COMMIT" if step == "commit" else "ROLLBACK"}}],
                    allow_retry=False,
                    baton=baton,
                )
                self._check_step_errors(response)
        except TursoError as e:
            if step == "commit":
                # Commit failures must surface (data may not be durably written).
                raise
            print(f"[turso] transaction {step} failed (ignored): {e}")

    def commit(self):
        self._end_transaction("commit")

    def rollback(self):
        self._end_transaction("rollback")

    def close(self):
        if self._baton:
            try:
                self.rollback()
            except Exception:
                pass
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
            stmt = {"type": "execute", "stmt": {"sql": sql_text}}
            baton = self.conn._baton
            started_txn = False

            if baton is not None:
                # Join the open interactive transaction.
                response = self.conn._pipeline([stmt], allow_retry=False, baton=baton)
            elif not is_query and self.conn._txn_ok:
                # First WRITE with no open transaction. On the Turso HTTP
                # API a transaction is a baton-bound session: send BEGIN as
                # a plain SQL statement plus the real statement in one
                # request; the returned baton keeps that session (and its
                # open transaction) alive for subsequent statements until
                # COMMIT/ROLLBACK finalizes it.
                try:
                    response = self.conn._pipeline([
                        {"type": "execute", "stmt": {"sql": "BEGIN"}},
                        stmt,
                    ], allow_retry=False)
                except TursoError:
                    # Server rejected the protocol outright (e.g. HTTP 400 on
                    # the request). Degrade to autocommit — the previous,
                    # proven behavior — instead of failing every write.
                    self.conn._txn_ok = False
                    print("[turso] BEGIN rejected by server; falling back to autocommit mode")
                    response = self.conn._pipeline([stmt], allow_retry=False)
                else:
                    results = response.get("results") or []
                    begin_item = (results[0] if results else {}) or {}
                    if begin_item.get("error"):
                        # BEGIN failed server-side (e.g. explicit transactions
                        # unsupported) — same degradation path.
                        self.conn._txn_ok = False
                        print("[turso] BEGIN failed on server "
                              f"({(begin_item.get('error') or {}).get('message')}); "
                              "falling back to autocommit mode")
                        response = self.conn._pipeline([stmt], allow_retry=False)
                    elif not response.get("baton"):
                        # BEGIN succeeded but no baton came back: the open
                        # transaction can never be committed, so its effects
                        # would be lost. Re-run the statement in autocommit
                        # and disable transactions for this connection.
                        self.conn._txn_ok = False
                        print("[turso] CRITICAL: BEGIN succeeded but no baton returned; "
                              "re-running statement in autocommit mode")
                        response = self.conn._pipeline([stmt], allow_retry=False)
                    else:
                        started_txn = True
            else:
                # Read (or autocommit mode): single statement, no baton.
                # Retrying a write could execute it twice (the first attempt
                # may have committed server-side before the client saw the
                # response), so only read-only statements are retryable.
                response = self.conn._pipeline([stmt], allow_retry=is_query)

            if started_txn or baton is not None:
                new_baton = response.get("baton")
                if new_baton:
                    self.conn._baton = new_baton

            self.conn._check_step_errors(response)
            results = response.get("results") or []
            if not results:
                raise TursoError(f"Invalid Turso pipeline response: {response}")
            # For [begin, execute] pipelines the execute step is last; take
            # it and validate the inner response type (real Turso answers
            # with {"type": "execute", "result": ...} inside the step).
            item = results[-1] or {}
            result = item.get("response")
            if not isinstance(result, dict) or result.get("type") not in ("execute",):
                error = item.get("error") or response.get("error")
                message = error.get("message") if isinstance(error, dict) else str(error or item)
                self._raise_statement_error(message)
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
        for params in params_list:
            self.execute(sql, params)
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