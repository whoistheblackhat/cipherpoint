#!/usr/bin/env bash
# CipherPoint local end-to-end test runner.
# Starts a mock Turso server + the backend against it, runs both test
# phases, then a production-mode docs check. Never touches production.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
BACKEND="$HERE/../backend"
VENV="${CP_VENV:-$HOME/cp-test-venv}"
DB="${CP_DB:-/tmp/cp_test.db}"
BASE_PORT=8001
MOCK_PORT=9800

# Pre-flight: kill anything already listening on our ports (stale runs)
for PORT in "$BASE_PORT" 8002 "$MOCK_PORT"; do
  PID=$(ss -ltnp 2>/dev/null | grep ":$PORT " | grep -oP 'pid=\K[0-9]+' | head -1)
  [ -n "$PID" ] && kill -9 "$PID" 2>/dev/null && echo ">>> killed stale pid $PID on :$PORT"
done
sleep 1

cleanup() {
  [ -n "${APP_PID:-}" ] && kill -9 "$APP_PID" 2>/dev/null
  [ -n "${MOCK_PID:-}" ] && kill -9 "$MOCK_PID" 2>/dev/null
  [ -n "${APP_PID2:-}" ] && kill -9 "$APP_PID2" 2>/dev/null
}
trap cleanup EXIT

rm -f "$DB"

echo ">>> starting mock Turso on :$MOCK_PORT"
python3 "$HERE/mock_turso.py" "$MOCK_PORT" "$DB" &
MOCK_PID=$!
sleep 1

APP_ENV=(
  TURSO_URL="http://127.0.0.1:$MOCK_PORT"
  TURSO_AUTH_TOKEN=local-test
  ENV=development
  WORKER_ID=2
  ADMIN_PASSWORD=LocalTestAdmin123
  SECRET_KEY=local-test-secret-0123456789abcdef-0123456789abcdef
  TURNSTILE_ENABLED=false
  TELEGRAM_BOT_TOKENS=
  TELEGRAM_ADMIN_BOT_TOKEN=
  REPORT_BOT_TOKEN=
  TELEGRAM_ADMIN_CHAT_ID=
  TELEGRAM_CHANNEL_ID=
  FRONTEND_URL=
)

echo ">>> starting backend on :$BASE_PORT (phase A)"
env "${APP_ENV[@]}" "$VENV/bin/python" -m uvicorn main:app --host 127.0.0.1 --port "$BASE_PORT" --app-dir "$BACKEND" > /tmp/cp_app_a.log 2>&1 &
APP_PID=$!
sleep 8
python3 "$HERE/e2e_phase_a.py" || true

echo
echo ">>> restarting backend to clear in-memory signup buckets (phase B)"
kill -9 "$APP_PID" 2>/dev/null; wait "$APP_PID" 2>/dev/null
env "${APP_ENV[@]}" "$VENV/bin/python" -m uvicorn main:app --host 127.0.0.1 --port "$BASE_PORT" --app-dir "$BACKEND" > /tmp/cp_app_b.log 2>&1 &
APP_PID2=$!
sleep 8
python3 "$HERE/e2e_phase_b.py" || true

echo
echo ">>> production-mode check: /docs must be disabled"
kill -9 "$APP_PID2" 2>/dev/null; wait "$APP_PID2" 2>/dev/null
env "${APP_ENV[@]}" ENV=production "$VENV/bin/python" -m uvicorn main:app --host 127.0.0.1 --port 8002 --app-dir "$BACKEND" > /tmp/cp_app_prod.log 2>&1 &
APP_PID2=$!
sleep 8
DOCS=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8002/docs)
OPENAPI=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8002/openapi.json)
HEALTH=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8002/api/health)
echo "    /docs -> $DOCS (want 404)   /openapi.json -> $OPENAPI (want 404)   /api/health -> $HEALTH (want 200)"
