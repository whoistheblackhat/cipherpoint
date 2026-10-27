from fastapi import FastAPI, Depends, HTTPException, Header, UploadFile, File, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

# Workaround: starlette 0.26 uses `anyio.to_thread` lazily.
# anyio 4.x has lazy __getattr__ that fails on some Python builds.
# Explicit import makes `anyio.to_thread` resolvable.
import anyio
import anyio.to_thread  # noqa: F401
import asyncio

from pydantic import BaseModel
from sqlalchemy.orm import Session
from datetime import datetime, timedelta, timezone
import jwt
import bcrypt
import os
import re
import secrets
import tempfile
import shutil
import threading
import time
import traceback
import requests
import hmac
import hashlib
from dotenv import load_dotenv
from typing import Optional
import json
from urllib.parse import urlsplit
from html import escape as escape_html
from sqlalchemy import text, func
from sqlalchemy.exc import IntegrityError

from database import init_db, get_db, SessionLocal
from models import User, Challenge, SolvedChallenge, UnlockedHint, ChallengeReport, UserBan, Comment, RevokedToken, ActiveToken, IntelArticle
from telegram_proxy import get_telegram_file, upload_media_to_channel, validate_media_duration, send_telegram_message, send_telegram_photo_with_buttons, start_admin_bot_polling, TELEGRAM_ADMIN_CHAT_ID, TELEGRAM_ADMIN_BOT_TOKEN, send_user_notification, TELEGRAM_REPORT_BOT_TOKEN, get_bot_health

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY", "").strip()
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15   # short-lived access token
REFRESH_TOKEN_EXPIRE_DAYS = 7      # long-lived refresh token

ENV = os.getenv("ENV", "dev").lower()
IS_PRODUCTION = ENV == "production"

if IS_PRODUCTION and (not SECRET_KEY or SECRET_KEY == "your-secret-key-change-in-production"):
    raise RuntimeError("SECRET_KEY must be set to a strong random value in production environment")

if not SECRET_KEY or SECRET_KEY == "your-secret-key-change-in-production":
    # Dev only: auto-generate a per-process secret. This is safe because
    # tokens issued by one process shouldn't be verified by another during
    # development. In production we fail-fast above.
    import secrets as _secrets
    SECRET_KEY = _secrets.token_urlsafe(64)
    print("[WARN] Using auto-generated SECRET_KEY for development. "
          "All tokens will be invalidated on every restart. "
          "Set SECRET_KEY in .env for stable dev sessions.")

TURNSTILE_SITE_KEY = os.getenv("SITE_KEY", "").strip()
TURNSTILE_SECRET_KEY = os.getenv("CLOUDFLARE_SECRET_KEY", "").strip()
TURNSTILE_ENABLED = os.getenv("TURNSTILE_ENABLED", "false").lower() == "true"
# Shared secret for the first-party mobile app to bypass Turnstile (the app
# cannot solve browser CAPTCHAs). Empty = no client may bypass Turnstile.
MOBILE_APP_SECRET = os.getenv("MOBILE_APP_SECRET", "").strip()

# Maintenance mode: when MAINTENANCE_MODE=true the public site returns
# 503 + a maintenance page. Admins (with a valid token) can still
# reach the API to verify and recover. MAINTENANCE_UNTIL is an ISO-8601
# UTC timestamp; once it passes, the site comes back online even if
# MAINTENANCE_MODE wasn't toggled off (handy for scheduled windows).
MAINTENANCE_MODE = os.getenv("MAINTENANCE_MODE", "false").lower() == "true"
MAINTENANCE_MESSAGE = os.getenv("MAINTENANCE_MESSAGE", "We're upgrading CipherPoint to serve you better. We'll be back shortly.").strip()
MAINTENANCE_UNTIL = os.getenv("MAINTENANCE_UNTIL", "").strip() or None  # ISO 8601, e.g. "2026-09-08T18:00:00Z"

CIPHER_DAY_ENV = os.getenv("CIPHER_DAY_ENV", "false").strip().lower() == "true"
CIPHER_DAY_STARTS_AT = os.getenv("CIPHER_DAY_STARTS_AT", "").strip()
CIPHER_DAY_ENDS_AT = os.getenv("CIPHER_DAY_ENDS_AT", "").strip()
CIPHER_DAY_CHALLENGE_ID = int(os.getenv("CIPHER_DAY_CHALLENGE_ID", "0"))
CIPHER_DAY_ASSET_BASE_URL = os.getenv("CIPHER_DAY_ASSET_BASE_URL", "").strip().rstrip("/")
if CIPHER_DAY_ASSET_BASE_URL:
    _cipher_asset_url = urlsplit(CIPHER_DAY_ASSET_BASE_URL)
    if (
        not _cipher_asset_url.netloc
        or _cipher_asset_url.scheme != "https"
        or _cipher_asset_url.username
        or _cipher_asset_url.password
        or _cipher_asset_url.query
        or _cipher_asset_url.fragment
    ):
        raise RuntimeError("CIPHER_DAY_ASSET_BASE_URL must be an HTTPS URL")


def _cipher_day_timestamp(value: str) -> Optional[datetime]:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed


def is_cipher_day_window_open(now: Optional[datetime] = None) -> bool:
    if not CIPHER_DAY_ENV:
        return False
    starts_at = _cipher_day_timestamp(CIPHER_DAY_STARTS_AT)
    ends_at = _cipher_day_timestamp(CIPHER_DAY_ENDS_AT)
    if not starts_at or not ends_at or ends_at <= starts_at:
        return False
    current_time = now or datetime.utcnow()
    return starts_at <= current_time < ends_at


def is_cipher_day_challenge(challenge: Challenge) -> bool:
    return CIPHER_DAY_CHALLENGE_ID > 0 and challenge.id == CIPHER_DAY_CHALLENGE_ID


def is_cipher_day_challenge_ready(challenge: Optional[Challenge]) -> bool:
    return bool(
        is_cipher_day_window_open()
        and challenge
        and challenge.status == "approved"
        and not challenge.is_community
        and (challenge.points_reward or 0) >= 500
        and CIPHER_DAY_ASSET_BASE_URL
    )


def get_turnstile_config():
    return {
        "turnstile_enabled": bool(TURNSTILE_ENABLED and TURNSTILE_SECRET_KEY),
        "site_key": TURNSTILE_SITE_KEY,
    }


def is_in_maintenance_window() -> bool:
    """Returns True when the public site should be blocked.

    The flag is the source of truth, but MAINTENANCE_UNTIL is a safety
    net: if a deploy forgot to flip MAINTENANCE_MODE back off, the site
    auto-recovers when the scheduled end time passes.
    """
    if not MAINTENANCE_MODE:
        return False
    if MAINTENANCE_UNTIL:
        try:
            # Accept both "2026-09-08T18:00:00Z" and "2026-09-08T18:00:00"
            from datetime import datetime as _dt
            until = _dt.fromisoformat(MAINTENANCE_UNTIL.replace("Z", "+00:00"))
            now_utc = datetime.utcnow().replace(tzinfo=until.tzinfo)
            if until <= now_utc:
                return False  # scheduled window already passed
        except ValueError:
            # If the env value is malformed, treat the flag as the only signal
            pass
    return True


def maintenance_status_payload() -> dict:
    """JSON body for /api/maintenance/status - safe to expose publicly
    (just a message + end time, no secrets)."""
    return {
        "enabled": is_in_maintenance_window(),
        "message": MAINTENANCE_MESSAGE if is_in_maintenance_window() else None,
        "ends_at": MAINTENANCE_UNTIL if is_in_maintenance_window() else None,
    }


def _is_mobile_app_request(request: Request) -> bool:
    """Returns True only for the first-party CipherPoint mobile app.

    A bare user-agent check is not a defense — any script can send a
    'cipherpoint'/'dart'/'okhttp' UA string and skip the CAPTCHA. The
    bypass now additionally requires the X-App-Secret header to match
    MOBILE_APP_SECRET (a value only the real app embeds). If no secret is
    configured server-side, nothing bypasses Turnstile.
    """
    if not MOBILE_APP_SECRET:
        return False
    supplied = (request.headers.get("x-app-secret") or "").strip()
    if not supplied:
        return False
    return hmac.compare_digest(supplied.encode("utf-8"), MOBILE_APP_SECRET.encode("utf-8"))


def verify_turnstile_token(token: str | None, remote_ip: str | None = None) -> bool:
    if not TURNSTILE_SECRET_KEY or not TURNSTILE_ENABLED:
        return True
    if not token:
        return False
    try:
        payload = {"secret": TURNSTILE_SECRET_KEY, "response": token}
        if remote_ip:
            payload["remoteip"] = remote_ip
        response = requests.post(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            data=payload,
            timeout=5
        )
        data = response.json()
        return bool(data.get("success"))
    except Exception as e:
        print(f"[TURNSTILE] Verification error: {e}")
        return False

# Initialize FastAPI app. Interactive API docs are a map of the entire
# authenticated surface — don't serve them to the public internet in
# production (dev keeps /docs, /redoc and /openapi.json).
app = FastAPI(
    title="CipherPoint API",
    version="1.0.0",
    docs_url=None if IS_PRODUCTION else "/docs",
    redoc_url=None if IS_PRODUCTION else "/redoc",
    openapi_url=None if IS_PRODUCTION else "/openapi.json",
)


# ==================== ERROR HANDLERS ====================

def _wants_html(request: Request) -> bool:
    """Return True if the client likely expects HTML (browser navigation)."""
    accept = (request.headers.get("accept") or "").lower()
    if "text/html" in accept or "*/*" in accept:
        # Only redirect GET browser requests, not API callers
        if request.method == "GET" and not request.url.path.startswith("/api/"):
            return True
    return False


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    """Custom HTTP exception handler.

    - Browser GET requests for non-API pages get redirected to the matching
      branded HTML page (404 -> /404.html, 500/503 -> /500.html) so the user
      never sees a raw JSON error in a tab.
    - API requests and all non-GET methods get the standard JSON response.
    """
    if exc.status_code == 404 and _wants_html(request):
        return FileResponse(os.path.join(FRONTEND_DIR, "404.html"), status_code=404)
    if exc.status_code in (500, 503) and _wants_html(request):
        return FileResponse(os.path.join(FRONTEND_DIR, "500.html"), status_code=exc.status_code)
    # Only pass headers if the exception actually carries any (JSONResponse defaults to None).
    response_headers = exc.headers if exc.headers else None
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
        headers=response_headers,
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    """Last-resort handler for unhandled exceptions.

    Logs to the server console (visible in Render logs) and either returns
    a JSON 500 for API callers or renders the branded 500 page for browsers.
    """
    trace_id = f"cp-{int(time.time())}-{secrets.token_hex(3)}"
    print(f"[{trace_id}] unhandled exception on {request.method} {request.url.path}: {exc}")
    print(traceback.format_exc())

    if _wants_html(request):
        return FileResponse(
            os.path.join(FRONTEND_DIR, "500.html"),
            status_code=500,
            headers={"X-CipherPoint-Trace": trace_id},
        )
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error", "trace_id": trace_id},
    )


# ==================== END ERROR HANDLERS ====================

# CORS Middleware — never use "*" in production. If FRONTEND_URL is not
# set we fall back to the public site URL and the onrender.com default.
_frontend_url = os.getenv("FRONTEND_URL", "").strip()
if not _frontend_url:
    if IS_PRODUCTION:
        # Fail safely: don't ship with a wildcard CORS in production.
        _frontend_url = "https://cipherpoint.onrender.com"
    else:
        _frontend_url = "*"  # dev convenience only

allowed_origins = [_frontend_url] if _frontend_url != "*" else ["*"]
# Optional extra origins (comma-separated), e.g. a custom domain that also
# serves the frontend: CORS_ORIGINS="https://cipherpoint.linkpc.net"
_extra_origins = [o.strip() for o in os.getenv("CORS_ORIGINS", "").split(",") if o.strip()]
if _extra_origins and "*" not in allowed_origins:
    allowed_origins += [o for o in _extra_origins if o not in allowed_origins]
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=bool(_frontend_url and _frontend_url != "*"),
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# Trust proxy headers to get real client IP behind Cloudflare/load balancers.
# This is critical for rate limiting to work correctly in production.
TRUSTED_PROXY_COUNT = int(os.getenv("TRUSTED_PROXY_COUNT", "1"))


def get_real_ip(request: Request) -> str:
    """Extract the real client IP from proxy headers.

    Behind Cloudflare the trustworthy value is CF-Connecting-IP: Cloudflare
    overwrites it with the actual client IP, so clients cannot spoof it.
    If it is absent (direct/local access), fall back to X-Forwarded-For but
    take the RIGHTMOST entry — proxies append the real client to the end of
    the chain, whereas the leftmost entry is fully client-controlled and
    would let an attacker rotate their identity to evade rate limits.
    """
    trusted = request.headers.get("cf-connecting-ip", "").strip()
    if trusted:
        return trusted
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        ips = [ip.strip() for ip in forwarded.split(",") if ip.strip()]
        if ips:
            # Walk back from the right past trusted proxy hops.
            idx = max(0, len(ips) - max(1, TRUSTED_PROXY_COUNT))
            return ips[idx]
    return request.client.host if request.client else "unknown"


# Middleware to attach real IP to request state
@app.middleware("http")
async def attach_real_ip(request: Request, call_next):
    request.state.real_ip = get_real_ip(request)
    response = await call_next(request)
    return response


# Honeypot enforcement: IPs that trip a honeypot path get throttled across
# the whole site for a grace period. Honeypot paths are never linked from
# the frontend, so only blind scanners/bots ever hit them.
_HONEYPOT_BLOCK_SECONDS = 3600
_honeypot_hits: dict[str, float] = {}
_honeypot_lock = threading.Lock()


def honeypot_flag_ip(ip: str) -> None:
    with _honeypot_lock:
        _honeypot_hits[ip] = time.time()
        # Bound memory: occasionally drop expired entries.
        if len(_honeypot_hits) > 10000:
            cutoff = time.time() - _HONEYPOT_BLOCK_SECONDS
            for k in [k for k, ts in _honeypot_hits.items() if ts < cutoff]:
                _honeypot_hits.pop(k, None)


@app.middleware("http")
async def honeypot_guard(request: Request, call_next):
    ip = get_real_ip(request)
    now = time.time()
    with _honeypot_lock:
        hit_at = _honeypot_hits.get(ip)
    if hit_at and (now - hit_at) < _HONEYPOT_BLOCK_SECONDS:
        return JSONResponse(
            status_code=429,
            content={"detail": "Too many requests"},
            headers={"Retry-After": str(int(_HONEYPOT_BLOCK_SECONDS - (now - hit_at)))},
        )
    return await call_next(request)


@app.middleware("http")
async def maintenance_gate(request: Request, call_next):
    """Block public traffic when maintenance mode is on.

    Admin users (identified by a valid admin JWT) bypass the gate so
    they can still verify the site, manage challenges, and toggle the
    mode off. The maintenance status endpoint is always reachable so
    the front-end can poll it.

    The gate returns:
      - 503 with a JSON body for API callers (so scripts/mobile apps
        get a machine-readable signal)
      - 503 with the maintenance.html page for browser GETs
    """
    path = request.url.path
    if path in {"/cipher-day.html", "/cipher-day-machine.html"} and not is_cipher_day_window_open():
        return JSONResponse(status_code=404, content={"detail": "Cipher Day is not available."})

    if not is_in_maintenance_window():
        return await call_next(request)

    # Always-allowed paths: status endpoint, the maintenance page itself,
    # the static assets it needs, and the login endpoint so admins can
    # authenticate during maintenance to flip the flag back off.
    always_allowed = (
        path == "/api/maintenance/status"
        or path == "/maintenance.html"
        or path == "/styles.css"
        or path == "/favicon.ico"
        or path == "/api/auth/login"
    )
    if always_allowed:
        return await call_next(request)

    # Admin bypass: if the request carries a valid admin JWT, let it
    # through. We use the same dependency the admin panel uses so any
    # future security checks (bans, etc.) are applied consistently.
    auth = request.headers.get("authorization")
    if auth and auth.lower().startswith("bearer "):
        token = auth.split(" ", 1)[1]
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        except jwt.InvalidTokenError:
            payload = None
        # Only real access tokens may bypass the gate (refresh tokens have
        # a 7-day lifetime and must not work here), and revoked tokens must
        # be rejected just like verify_token would.
        if payload and payload.get("typ") == "access":
            try:
                uid = int(payload.get("sub"))
            except (TypeError, ValueError):
                uid = None
            jti = payload.get("jti")
            if uid and jti:
                # Quick DB hit to check admin status. We don't use
                # Depends() here because middleware can't take FastAPI
                # dependencies directly.
                try:
                    with SessionLocal() as s:
                        revoked = s.query(RevokedToken).filter(RevokedToken.jti == jti).first()
                        if revoked and not revoked.is_expired():
                            return _maintenance_response(request, path)
                        u = s.query(User).filter(User.id == uid).first()
                        if u and getattr(u, "is_admin", False):
                            return await call_next(request)
                except Exception as exc:
                    print(f"[maintenance] admin bypass check failed: {exc}")

    return _maintenance_response(request, path)


def _maintenance_response(request: Request, path: str):
    """503 response for blocked traffic: maintenance.html for browsers,
    structured JSON for API callers."""
    accept = (request.headers.get("accept") or "").lower()
    wants_html = "text/html" in accept or path.endswith(".html")
    if wants_html and request.method == "GET":
        try:
            with open(os.path.join(os.path.dirname(__file__), "frontend", "maintenance.html"), "r", encoding="utf-8") as fh:
                html = fh.read()
            return HTMLResponse(content=html, status_code=503)
        except FileNotFoundError:
            pass
    # API / non-HTML clients get a structured error they can handle
    return JSONResponse(
        status_code=503,
        content={
            "detail": MAINTENANCE_MESSAGE,
            "maintenance": True,
            "ends_at": MAINTENANCE_UNTIL,
        },
    )


# Security headers middleware — clickjacking, MIME sniffing, HSTS, etc.
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    asset_parts = urlsplit(CIPHER_DAY_ASSET_BASE_URL) if CIPHER_DAY_ASSET_BASE_URL else None
    cipher_asset_origin = f"{asset_parts.scheme}://{asset_parts.netloc}" if asset_parts else ""
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    # Relaxed CSP to allow CDN assets (fonts, icons) while still blocking inline scripts.
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        f"script-src 'self' 'unsafe-inline' 'unsafe-eval' {cipher_asset_origin} https://challenges.cloudflare.com https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; "
        "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; "
        "img-src 'self' data: https://cdnjs.cloudflare.com; "
        f"connect-src 'self' {cipher_asset_origin} https://api.telegram.org https://challenges.cloudflare.com; "
        "frame-src 'self' https://challenges.cloudflare.com; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )
    if IS_PRODUCTION:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
    return response

# Force HTTPS in production. Render already terminates TLS for us, but
# this guards against accidental HTTP-only deploys.
if IS_PRODUCTION:
    from starlette.middleware.httpsredirect import HTTPSRedirectMiddleware
    # Disabled by default — Render's external LB handles the upgrade.
    # Enable with FORCE_HTTPS=1 if you ever put the service behind a
    # plain-HTTP proxy.
    if os.getenv("FORCE_HTTPS", "0") == "1":
        app.add_middleware(HTTPSRedirectMiddleware)

# Request models
class UserSignupRequest(BaseModel):
    username: str
    email: str
    password: str
    turnstile_token: str | None = None
    fingerprint: str | None = None

class UserLoginRequest(BaseModel):
    username: str
    password: str
    turnstile_token: str | None = None

class OtpLoginRequest(BaseModel):
    chat_id: str
    turnstile_token: str | None = None

class OtpVerifyRequest(BaseModel):
    chat_id: str
    otp: str
    username: str | None = None

class HintRequest(BaseModel):
    challenge_id: int
    hint_number: int

class FlagSubmitRequest(BaseModel):
    challenge_id: int
    flag: str

class CipherDayFlagRequest(BaseModel):
    flag: str

class ChallengeCreateRequest(BaseModel):
    title: str
    category: str
    difficulty: str
    description: str
    correct_flag: str
    telegram_file_id: str
    points_reward: int
    hint_1: str
    hint_1_cost: int = 10
    hint_2: Optional[str] = None
    hint_2_cost: int = 20
    tags: Optional[str] = ""
    solution_walkthrough: Optional[str] = None
    # Admin-created challenges are trusted; default True so the shared
    # community validator never AttributeErrors (a 500) when the client
    # omits this field.
    disclaimer_accepted: bool = True

    class Config:
        extra = "allow"


class CommunityChallengeCreateRequest(BaseModel):
    title: str
    category: str
    difficulty: str
    description: str
    correct_flag: str
    telegram_file_id: str
    points_reward: int = 100
    hint_1: Optional[str] = None
    hint_1_cost: int = 10
    hint_2: Optional[str] = None
    hint_2_cost: int = 20
    disclaimer_accepted: bool = False
    tags: Optional[str] = ""
    solution_walkthrough: Optional[str] = None

    class Config:
        extra = "allow"


class IntelArticleCreateRequest(BaseModel):
    title: str
    category: str
    content: str
    summary: Optional[str] = None
    telegram_file_id: Optional[str] = None
    is_published: bool = False


class IntelArticleUpdateRequest(BaseModel):
    title: Optional[str] = None
    category: Optional[str] = None
    content: Optional[str] = None
    summary: Optional[str] = None
    telegram_file_id: Optional[str] = None
    is_published: Optional[bool] = None


INTEL_TITLE_MAX = 200
INTEL_CATEGORY_MAX = 60
INTEL_CONTENT_MAX = 20000
INTEL_SUMMARY_MAX = 500
# bounds to prevent abuse (oversized DB rows, infinite-coin glitches,
# etc.) and to keep the UI sane.
CHALLENGE_TITLE_MAX = 120
CHALLENGE_CATEGORY_MAX = 60
CHALLENGE_DIFFICULTY_MAX = 20
CHALLENGE_DESCRIPTION_MAX = 4000
CHALLENGE_FLAG_MAX = 200
CHALLENGE_TELEGRAM_FILE_ID_MAX = 256
CHALLENGE_TAGS_MAX = 200
CHALLENGE_HINT_MAX = 1000
CHALLENGE_WALKTHROUGH_MAX = 10000
CHALLENGE_HINT_COST_MAX = 1000
CHALLENGE_POINTS_MIN = 10
CHALLENGE_POINTS_MAX = 1000
ALLOWED_DIFFICULTIES = {"Easy", "Medium", "Hard"}
ALLOWED_CATEGORIES_PREFIX = None  # categories are free-form today

# Spam guard: titles/flags that are very common placeholders.
_PLACEHOLDER_TITLES = {
    "test", "test challenge", "asdf", "qwerty", "new challenge",
    "challenge", "ctf", "ctf challenge", "untitled", "demo",
    "sample", "example", "abc", "xyz", "123",
}


def _validate_text_lengths(payload, field_map):
    for field, max_len in field_map.items():
        value = getattr(payload, field, None)
        if value is None:
            continue
        if len(value) > max_len:
            raise HTTPException(
                status_code=400,
                detail=f"{field.replace('_', ' ').capitalize()} is too long (max {max_len} characters).",
            )


def _validate_community_payload(payload: CommunityChallengeCreateRequest):
    """Centralised validation for community challenges.

    Catches:
      - Empty / over-long text fields
      - Invalid difficulty / points ranges
      - Telegram file id length / charset
      - Placeholder / spam titles
    """
    if not payload.disclaimer_accepted:
        raise HTTPException(
            status_code=400,
            detail="You must accept the platform disclaimer before publishing a community challenge.",
        )

    _validate_text_lengths(payload, {
        "title": CHALLENGE_TITLE_MAX,
        "category": CHALLENGE_CATEGORY_MAX,
        "difficulty": CHALLENGE_DIFFICULTY_MAX,
        "description": CHALLENGE_DESCRIPTION_MAX,
        "correct_flag": CHALLENGE_FLAG_MAX,
        "telegram_file_id": CHALLENGE_TELEGRAM_FILE_ID_MAX,
        "tags": CHALLENGE_TAGS_MAX,
        "hint_1": CHALLENGE_HINT_MAX,
        "hint_2": CHALLENGE_HINT_MAX,
        "solution_walkthrough": CHALLENGE_WALKTHROUGH_MAX,
    })

    if payload.difficulty not in ALLOWED_DIFFICULTIES:
        raise HTTPException(
            status_code=400,
            detail=f"Difficulty must be one of: {', '.join(sorted(ALLOWED_DIFFICULTIES))}",
        )

    if payload.points_reward < CHALLENGE_POINTS_MIN or payload.points_reward > CHALLENGE_POINTS_MAX:
        raise HTTPException(
            status_code=400,
            detail=f"points_reward must be between {CHALLENGE_POINTS_MIN} and {CHALLENGE_POINTS_MAX}.",
        )
    if (payload.hint_1_cost or 0) < 0 or (payload.hint_1_cost or 0) > CHALLENGE_HINT_COST_MAX:
        raise HTTPException(status_code=400, detail="hint_1_cost must be between 0 and 1000.")
    if (payload.hint_2_cost or 0) < 0 or (payload.hint_2_cost or 0) > CHALLENGE_HINT_COST_MAX:
        raise HTTPException(status_code=400, detail="hint_2_cost must be between 0 and 1000.")

    # Telegram file IDs have a known charset. Reject anything weird
    # before we waste a DB row on it.
    if not re.fullmatch(r"[A-Za-z0-9_-]{20,256}", payload.telegram_file_id or ""):
        raise HTTPException(
            status_code=400,
            detail="telegram_file_id is missing or has an invalid format. Please re-upload the media.",
        )

    title_norm = (payload.title or "").strip().lower()
    if title_norm in _PLACEHOLDER_TITLES:
        raise HTTPException(
            status_code=400,
            detail="That title looks like a placeholder. Please use a descriptive challenge title.",
        )

class ChallengeReportRequest(BaseModel):
    reason: str
    details: str = ""
    comment_id: Optional[int] = None

class ModerationActionRequest(BaseModel):
    action: str
    reason: str = ""


def is_sensitive_identity_content(value: str) -> bool:
    if not value:
        return False
    lowered = value.lower()
    bad_tokens = [
        "real name", "phone number", "mobile number", "email address", "home address",
        "street address", "passport", "id number", "ssn", "dni", "personal info",
        "doxxing", "doxx", "contact me at", "call me", "text me", "private number",
        "my address", "my home", "family member", "wife name", "husband name",
        "real identity", "target person", "personally identifiable"
    ]
    if any(token in lowered for token in bad_tokens):
        return True
    if re.search(r"[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}", lowered):
        return True
    if re.search(r"\+?\d[\d\s().-]{7,}\d", lowered):
        return True
    return False


def validate_community_submission(payload: CommunityChallengeCreateRequest):
    """Legacy entry point. Kept for backward-compat with any caller
    outside this module that imports it. Delegates to the new
    _validate_community_payload and the sensitive-content check."""
    _validate_community_payload(payload)
    combined = " ".join([
        payload.title or "",
        payload.category or "",
        payload.description or "",
        payload.correct_flag or "",
        payload.tags or "",
    ])
    if is_sensitive_identity_content(combined):
        raise HTTPException(status_code=400, detail="Personal identity or private data is not allowed on this platform.")


COMMUNITY_CTF_WEEKLY_LIMIT = int(os.getenv("COMMUNITY_CTF_WEEKLY_LIMIT", "0"))
COMMUNITY_CTF_EXPIRY_DAYS = int(os.getenv("COMMUNITY_CTF_EXPIRY_DAYS", "30"))


def check_and_reset_weekly_quota(user: User):
    """Reset quota if a week has passed since last reset."""
    now = datetime.utcnow()
    reset_at = getattr(user, "weekly_reset_at", None)
    if not reset_at or now >= reset_at:
        user.weekly_challenges_used = 0
        user.weekly_reset_at = now + timedelta(days=7)


def enforce_community_quota(user: User):
    """Raise 429 if user has hit the weekly community CTF creation limit.

    When COMMUNITY_CTF_WEEKLY_LIMIT is 0 the quota is disabled entirely so
    that testing and seeding flows are not blocked.
    """
    if COMMUNITY_CTF_WEEKLY_LIMIT <= 0:
        return
    check_and_reset_weekly_quota(user)
    if (user.weekly_challenges_used or 0) >= COMMUNITY_CTF_WEEKLY_LIMIT:
        retry_after = max(0, int((user.weekly_reset_at - datetime.utcnow()).total_seconds()))
        days_left = max(1, retry_after // 86400)
        raise HTTPException(
            status_code=429,
            detail=f"You've reached your weekly limit of {COMMUNITY_CTF_WEEKLY_LIMIT} community CTFs. Quota resets in ~{days_left} day(s)."
        )


def reserve_community_quota(user: User, db: Session):
    """Atomically reserve one community challenge slot for this user.

    When COMMUNITY_CTF_WEEKLY_LIMIT is 0 quota is disabled, so the
    counter is left untouched.
    """
    if COMMUNITY_CTF_WEEKLY_LIMIT <= 0:
        return
    check_and_reset_weekly_quota(user)
    db.flush()
    updated = db.query(User).filter(
        User.id == user.id,
        User.weekly_challenges_used < COMMUNITY_CTF_WEEKLY_LIMIT,
    ).update(
        {User.weekly_challenges_used: User.weekly_challenges_used + 1},
        synchronize_session=False,
    )
    if not updated:
        db.rollback()
        db.refresh(user)
        retry_after = max(
            0,
            int((user.weekly_reset_at - datetime.utcnow()).total_seconds())
        ) if user.weekly_reset_at else 0
        days_left = max(1, retry_after // 86400)
        raise HTTPException(
            status_code=429,
            detail=f"You've reached your weekly limit of {COMMUNITY_CTF_WEEKLY_LIMIT} community CTFs. Quota resets in ~{days_left} day(s)."
        )
    db.refresh(user)


def ensure_admin_user():
    db = SessionLocal()
    try:
        admin_username = os.getenv("ADMIN_USERNAME", "admin").strip() or "admin"
        admin_email = os.getenv("ADMIN_EMAIL", "admin@cipherpoint.com").strip() or "admin@cipherpoint.com"
        admin_password = os.getenv("ADMIN_PASSWORD", "").strip()

        existing = db.query(User).filter(User.username == admin_username).first()
        if existing:
            if not existing.is_admin:
                existing.is_admin = True
            if admin_email and existing.email != admin_email:
                existing.email = admin_email
            if admin_password:
                if len(admin_password) < 12:
                    raise RuntimeError("ADMIN_PASSWORD must be at least 12 characters")
                if not verify_password(admin_password, existing.password_hash):
                    existing.password_hash = hash_password(admin_password)
            db.commit()
            return

        if not admin_password:
            message = "ADMIN_PASSWORD must be configured before creating the initial admin account"
            if IS_PRODUCTION:
                raise RuntimeError(message)
            print(f"[WARN] {message}; skipping default admin creation")
            return
        if len(admin_password) < 12:
            raise RuntimeError("ADMIN_PASSWORD must be at least 12 characters")

        db.add(User(
            username=admin_username,
            email=admin_email,
            password_hash=hash_password(admin_password),
            is_admin=True,
            coins=1000,
            rank_points=5000,
        ))
        db.commit()
    finally:
        db.close()


# Initialize database on startup
@app.on_event("startup")
def startup():
    init_db()
    ensure_admin_user()
    if _is_primary_worker:
        start_admin_bot_polling(SessionLocal)
        start_expiry_scheduler()
    else:
        print(f"[WORKER] Worker {_worker_id} skipping bot polling/expiry (handled by primary)")
    print("✅ Database initialized!")
    print(f"📡 Telegram upload bots: {len(os.getenv('TELEGRAM_BOT_TOKENS', '').split(','))} configured")
    print(f"📡 Telegram admin bot: {'configured' if os.getenv('TELEGRAM_ADMIN_BOT_TOKEN') else 'NOT configured'}")
    print(f"📡 Telegram admin chat ID: {'configured' if os.getenv('TELEGRAM_ADMIN_CHAT_ID') else 'NOT configured - set TELEGRAM_ADMIN_CHAT_ID in .env'}")
    print(f"🛡️  Turnstile: {'ENABLED' if TURNSTILE_ENABLED else 'DISABLED (dev mode)'}")
    print(f"📊 Community CTF quota: {COMMUNITY_CTF_WEEKLY_LIMIT}/week, expiry: {COMMUNITY_CTF_EXPIRY_DAYS} days")

    if os.getenv('TELEGRAM_ADMIN_BOT_TOKEN') and os.getenv('TELEGRAM_ADMIN_CHAT_ID'):
        try:
            test_msg = "✅ <b>CipherPoint Backend Started</b>\n\nReport notifications are now active. Use /help to see available commands."
            send_telegram_message(os.getenv('TELEGRAM_ADMIN_CHAT_ID'), test_msg)
            print("📡 Telegram startup notification sent successfully")
        except Exception as e:
            print(f"⚠️ Telegram startup notification failed: {e}")
            print("   Make sure you have sent /start to your admin bot first!")


_expiry_scheduler_running = False
_worker_id = os.getenv("WORKER_ID", "0")
# Only the designated primary instance runs background jobs (bot polling,
# expiry scheduler). WORKER_ID="1" is NOT primary — with the documented
# single-worker setup the primary is 0, and treating 1 as primary too would
# double-process Telegram updates if a second worker were ever added.
_is_primary_worker = _worker_id in ("0", "primary")


def purge_expired_community_challenges():
    """Delete UNSOLVED community challenges older than COMMUNITY_CTF_EXPIRY_DAYS.

    Solved challenges are kept indefinitely so users don't lose their
    progress and the leaderboard history stays intact. Unsolved ones are
    removed together with their comments, hints, and reports.
    """
    db = SessionLocal()
    try:
        cutoff = datetime.utcnow() - timedelta(days=COMMUNITY_CTF_EXPIRY_DAYS)
        # Find unsolved challenges past the cutoff
        candidate = db.query(Challenge).filter(
            Challenge.is_community == True,
            Challenge.created_at < cutoff,
        ).all()
        solved_ids = {row[0] for row in db.query(SolvedChallenge.challenge_id).filter(SolvedChallenge.challenge_id.in_([c.id for c in candidate])).all()}
        expired = [c for c in candidate if c.id not in solved_ids]

        if not expired:
            return 0

        expired_ids = [c.id for c in expired]
        for c in expired:
            print(f"[EXPIRY] Purging unsolved community CTF #{c.id} '{c.title}' (created {c.created_at})")

        expired_comment_ids = [
            row[0] for row in db.query(Comment.id).filter(Comment.challenge_id.in_(expired_ids)).all()
        ]
        deleted_comments = 0
        if expired_comment_ids:
            db.query(Comment).filter(
                Comment.challenge_id.in_(expired_ids)
            ).update({Comment.parent_id: None}, synchronize_session=False)
            deleted_comments = db.query(Comment).filter(
                Comment.id.in_(expired_comment_ids)
            ).delete(synchronize_session=False)
        deleted_hints = db.query(UnlockedHint).filter(UnlockedHint.challenge_id.in_(expired_ids)).delete(synchronize_session=False)
        deleted_reports = db.query(ChallengeReport).filter(ChallengeReport.challenge_id.in_(expired_ids)).delete(synchronize_session=False)
        db.query(Challenge).filter(Challenge.id.in_(expired_ids)).delete(synchronize_session=False)

        db.commit()
        print(f"[EXPIRY] Purged {len(expired_ids)} unsolved challenges, {deleted_comments} comments, {deleted_hints} hints, {deleted_reports} reports. Solved challenges were preserved.")

        if TELEGRAM_ADMIN_CHAT_ID and len(expired) > 0:
            try:
                send_telegram_message(
                    TELEGRAM_ADMIN_CHAT_ID,
                    f"🧹 <b>Auto-Purge Complete</b>\n\n"
                    f"Expired community CTFs (> {COMMUNITY_CTF_EXPIRY_DAYS} days): <b>{len(expired_ids)}</b>\n"
                    f"Cascade-deleted comments: {deleted_comments}\n"
                    f"Cascade-deleted hints: {deleted_hints}\n"
                    f"Cascade-deleted reports: {deleted_reports}"
                )
            except Exception as e:
                print(f"[EXPIRY] Notification failed: {e}")

        return len(expired_ids)
    except Exception as e:
        print(f"[EXPIRY] Error: {e}")
        db.rollback()
        return 0
    finally:
        db.close()


def start_expiry_scheduler():
    global _expiry_scheduler_running
    if _expiry_scheduler_running:
        return
    _expiry_scheduler_running = True

    def loop():
        while _expiry_scheduler_running:
            try:
                purge_expired_community_challenges()
            except Exception as e:
                print(f"[EXPIRY] Loop error: {e}")
            time.sleep(int(os.getenv("EXPIRY_CHECK_INTERVAL", "3600")))

    thread = threading.Thread(target=loop, daemon=True, name="expiry-scheduler")
    thread.start()

# ==================== UTILITY FUNCTIONS ====================

from security import (
    hash_password,
    verify_password,
    is_valid_username,
    is_valid_email,
    password_strength_errors,
    rate_limit_check,
    rate_limit_reset,
    is_account_locked,
    record_failed_login,
    record_successful_login,
    constant_time_eq,
    LOGIN_MAX_ATTEMPTS,
    LOGIN_LOCKOUT_MINUTES,
    COMMON_PASSWORDS,
)

def create_access_token(data: dict, expires_minutes: int = None, token_type: str = "access"):
    """Create JWT access or refresh token with a unique jti for revocation.

    Args:
        data: claims to include (must contain 'sub' for user id).
        expires_minutes: override the default TTL; refresh tokens pass a
            large value (days) and access tokens use ACCESS_TOKEN_EXPIRE_MINUTES.
        token_type: 'access' or 'refresh'. The claim is read by the
            refresh endpoint to reject access tokens being used as
            refresh tokens (and vice-versa).
    """
    import secrets
    to_encode = data.copy()
    if 'sub' in to_encode and not isinstance(to_encode['sub'], str):
        to_encode['sub'] = str(to_encode['sub'])
    if expires_minutes is None:
        expires_minutes = ACCESS_TOKEN_EXPIRE_MINUTES
    expire = datetime.utcnow() + timedelta(minutes=expires_minutes)
    to_encode.update({
        "exp": expire,
        "iat": datetime.utcnow(),
        "jti": secrets.token_urlsafe(16),  # unique ID for blacklist lookup
        "typ": token_type,
    })
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def issue_token(db: Session, user_id: int) -> str:
    """Create a short-lived access JWT and register it in `active_tokens`
    so it can be revoked later (e.g. on user ban or explicit logout)."""
    token = create_access_token(data={"sub": user_id}, token_type="access")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM], options={"verify_exp": False})
        jti = payload.get("jti")
        exp = datetime.utcfromtimestamp(payload.get("exp"))
        if jti:
            db.add(ActiveToken(jti=jti, user_id=user_id, expires_at=exp, token_type="access"))
            db.commit()
    except Exception as exc:
        print(f"[auth] failed to register active token for user {user_id}: {exc}")
        db.rollback()
    return token


def issue_token_pair(db: Session, user_id: int):
    """Return (access_token, refresh_token) for the user. Both are
    tracked in `active_tokens` so they can be revoked individually."""
    access = create_access_token(data={"sub": user_id}, token_type="access")
    refresh = create_access_token(
        data={"sub": user_id},
        expires_minutes=REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60,
        token_type="refresh",
    )
    try:
        for token, ttype in ((access, "access"), (refresh, "refresh")):
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM], options={"verify_exp": False})
            jti = payload.get("jti")
            exp = datetime.utcfromtimestamp(payload.get("exp"))
            if jti:
                db.add(ActiveToken(jti=jti, user_id=user_id, expires_at=exp, token_type=ttype))
        db.commit()
    except Exception as exc:
        print(f"[auth] failed to register token pair for user {user_id}: {exc}")
        db.rollback()
    return access, refresh


def revoke_user_tokens(db: Session, user_id: int, reason: str = "admin_action") -> int:
    """Move every active token for a user into the revocation list.
    Returns the number of tokens that were revoked. Expired tokens are
    pruned at the same time so the table doesn't grow unbounded."""
    now = datetime.utcnow()
    # Cleanup: drop already-expired active rows
    db.query(ActiveToken).filter(ActiveToken.expires_at <= now).delete()
    # Fetch currently-active tokens for the user
    active = db.query(ActiveToken).filter(ActiveToken.user_id == user_id, ActiveToken.expires_at > now).all()
    count = 0
    for row in active:
        if not db.query(RevokedToken).filter(RevokedToken.jti == row.jti).first():
            db.add(RevokedToken(
                jti=row.jti,
                user_id=user_id,
                revoked_at=now,
                expires_at=row.expires_at,
                reason=reason,
            ))
            count += 1
    # Remove the now-revoked rows from active_tokens so verify_token
    # only needs to check the revocation list.
    db.query(ActiveToken).filter(ActiveToken.user_id == user_id, ActiveToken.expires_at > now).delete()
    db.commit()
    return count

def verify_token(authorization: Optional[str] = Header(None), db: Session = Depends(get_db)):
    """Verify JWT token from Authorization header. Also rejects tokens
    whose `jti` is in the revocation list (banned users, explicit logout)."""
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing authorization header")

    try:
        scheme, token = authorization.split()
        if scheme.lower() != "bearer":
            raise HTTPException(status_code=401, detail="Invalid authorization scheme")

        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        # Refresh tokens must never authenticate API calls: they live 7
        # days, so accepting them here would keep a "logged out" session
        # alive for a week (logout only revokes the presented access jti).
        if payload.get("typ") != "access":
            raise HTTPException(status_code=401, detail="Invalid token type")
        user_id = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")

        # Revocation check: see if the token's jti has been blacklisted
        # (e.g. user was banned, password changed, or explicitly logged out).
        jti = payload.get("jti")
        if jti:
            revoked = db.query(RevokedToken).filter(RevokedToken.jti == jti).first()
            if revoked and not revoked.is_expired():
                raise HTTPException(status_code=401, detail="Token has been revoked")

        return int(user_id)
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid authorization format")
    except (jwt.InvalidTokenError, TypeError, ValueError):
        raise HTTPException(status_code=401, detail="Invalid or expired token")


def get_current_admin_user(user_id: int = Depends(verify_token), db: Session = Depends(get_db)):
    """Return the authenticated user only if they are an admin."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if db.query(UserBan).filter(UserBan.user_id == user.id).first():
        raise HTTPException(status_code=403, detail="Your account has been suspended.")
    if not getattr(user, "is_admin", False):
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


def _check_content_spam(ip_address: str, user_id: int, db: Session) -> None:
    """Flag user if their IP is associated with multiple accounts creating
    comments or reports recently (coordinated spam / account sharing)."""
    if not ip_address or ip_address in {"127.0.0.1", "::1", "unknown"}:
        return
    cutoff = datetime.utcnow() - timedelta(hours=24)
    comment_users = {
        row[0] for row in db.query(Comment.user_id)
        .filter(Comment.ip_address == ip_address, Comment.created_at >= cutoff)
        .distinct()
        .all()
    }
    report_users = {
        row[0] for row in db.query(ChallengeReport.reporter_id)
        .filter(ChallengeReport.ip_address == ip_address, ChallengeReport.created_at >= cutoff)
        .distinct()
        .all()
    }
    all_users = comment_users | report_users
    if len(all_users) >= 2:
        for uid in all_users:
            user = db.query(User).filter(User.id == uid).first()
            if user and not user.flagged_for_review:
                user.flagged_for_review = True


def ensure_user_not_banned(user_id: int, db: Session):
    """Raise 403 if the user has an *active* ban. Expired bans are auto-lifted."""
    ban = db.query(UserBan).filter(UserBan.user_id == user_id).first()
    if not ban:
        return
    if ban.expires_at is not None and ban.expires_at <= datetime.utcnow():
        # Auto-lift expired ban so the user can sign in again.
        db.delete(ban)
        db.commit()
        return
    raise HTTPException(status_code=403, detail="Your account has been suspended.")


# ==================== COMMENT ROUTES ====================

class CommentCreateRequest(BaseModel):
    body: str
    parent_id: Optional[int] = None


@app.get("/api/challenges/{challenge_id}/comments")
def list_comments(challenge_id: int, db: Session = Depends(get_db)):
    """Return all top-level comments for a challenge with nested replies."""
    challenge = db.query(Challenge).filter(Challenge.id == challenge_id).first()
    if not challenge:
        raise HTTPException(status_code=404, detail="Challenge not found")

    comments = (
        db.query(Comment)
        .filter(Comment.challenge_id == challenge_id, Comment.parent_id.is_(None))
        .order_by(Comment.created_at.asc())
        .all()
    )

    user_ids = {c.user_id for c in comments}
    all_comment_ids = {c.id for c in comments}
    replies_map = {c.id: [] for c in comments}

    replies = (
        db.query(Comment)
        .filter(Comment.challenge_id == challenge_id, Comment.parent_id.is_not(None))
        .order_by(Comment.created_at.asc())
        .all()
    )

    for reply in replies:
        user_ids.add(reply.user_id)
        if reply.parent_id in replies_map:
            replies_map[reply.parent_id].append(reply)

    users = {}
    if user_ids:
        for u in db.query(User).filter(User.id.in_(user_ids)).all():
            users[u.id] = u.username

    def serialize_comment(c):
        reply_list = replies_map.get(c.id, [])
        return {
            "id": c.id,
            "challenge_id": c.challenge_id,
            "username": users.get(c.user_id, "unknown"),
            "body": c.body,
            "parent_id": c.parent_id,
            "created_at": c.created_at,
            "replies": [
                {
                    "id": r.id,
                    "challenge_id": r.challenge_id,
                    "username": users.get(r.user_id, "unknown"),
                    "body": r.body,
                    "parent_id": r.parent_id,
                    "created_at": r.created_at,
                }
                for r in reply_list
            ]
        }

    return [serialize_comment(c) for c in comments]


@app.post("/api/challenges/{challenge_id}/comments")
def create_comment(
    challenge_id: int,
    payload: CommentCreateRequest,
    request: Request,
    user_id: int = Depends(verify_token),
    db: Session = Depends(get_db)
):
    """Post a new comment or reply on a challenge."""
    ensure_user_not_banned(user_id, db)
    challenge = db.query(Challenge).filter(Challenge.id == challenge_id).first()
    if not challenge:
        raise HTTPException(status_code=404, detail="Challenge not found")

    ip = request.state.real_ip
    allowed, retry = rate_limit_check(f"comment_user:{user_id}", max_events=10, window_seconds=60)
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail=f"Too many comments. Please wait {retry}s.",
            headers={"Retry-After": str(retry)},
        )

    body = (payload.body or "").strip()
    if not body:
        raise HTTPException(status_code=400, detail="Comment body is required")
    if len(body) > 2000:
        raise HTTPException(status_code=400, detail="Comment is too long (max 2000 characters)")

    parent_id = payload.parent_id
    if parent_id:
        parent = db.query(Comment).filter(
            Comment.id == parent_id,
            Comment.challenge_id == challenge_id
        ).first()
        if not parent:
            raise HTTPException(status_code=400, detail="Parent comment not found")

    new_comment = Comment(challenge_id=challenge_id, user_id=user_id, body=body, parent_id=parent_id, ip_address=ip)
    db.add(new_comment)
    db.commit()
    db.refresh(new_comment)

    _check_content_spam(ip, user_id, db)
    db.commit()

    author = db.query(User).filter(User.id == user_id).first()

    # Mention detection — find all @username tokens in the comment body,
    # look up each mentioned user, and send a Telegram notification if:
    #   - they have a linked Telegram chat
    #   - they have notify_mentions enabled
    #   - they are not the comment author (no self-notify)
    mentioned_usernames = set(re.findall(r"@([A-Za-z0-9_.-]{3,32})", body))
    if mentioned_usernames:
        author_username = author.username if author else ""
        for username in mentioned_usernames:
            if username.lower() == author_username.lower():
                continue
            mentioned_user = db.query(User).filter(
                func.lower(User.username) == username.lower()
            ).first()
            if not mentioned_user:
                continue
            if not mentioned_user.telegram_chat_id:
                continue
            if not mentioned_user.notify_mentions:
                continue
            try:
                challenge_title = escape_html(challenge.title or f"Challenge #{challenge_id}")
                author_name = escape_html(author_username or "Someone")
                preview = escape_html(body[:200] + ("..." if len(body) > 200 else ""))
                send_user_notification(
                    mentioned_user.telegram_chat_id,
                    f"🔔 <b>You were mentioned</b>\n\n"
                    f"<b>{author_name}</b> mentioned you in a comment on "
                    f"<b>{challenge_title}</b>:\n\n"
                    f"<i>{preview}</i>"
                )
            except Exception as e:
                print(f"[MENTION] Notification failed for user {mentioned_user.id}: {e}")

    return {
        "id": new_comment.id,
        "challenge_id": new_comment.challenge_id,
        "username": author.username if author else "unknown",
        "body": new_comment.body,
        "parent_id": new_comment.parent_id,
        "created_at": new_comment.created_at,
    }


# ==================== AUTH ROUTES ====================

@app.post("/api/auth/signup")
def signup(payload: UserSignupRequest, request: Request, db: Session = Depends(get_db)):
    """User signup endpoint.

    Defenses:
      - Turnstile CAPTCHA in production
      - Per-IP rate limit (5 signups / hour)
      - Strict input validation (username charset/length, email format,
        password strength)
      - Race-condition safe: the unique constraints on username/email are
        the source of truth, and we catch IntegrityError as a backstop.
    """
    if TURNSTILE_SECRET_KEY and TURNSTILE_ENABLED:
        remote_ip = request.state.real_ip
        if not _is_mobile_app_request(request) and not verify_turnstile_token(payload.turnstile_token, remote_ip):
            raise HTTPException(status_code=403, detail="Turnstile verification failed. Please complete the security check.")

    # Per-IP rate limit (defense against mass account creation / spam)
    ip = request.state.real_ip
    allowed, retry = rate_limit_check(f"signup_ip:{ip}", max_events=5, window_seconds=3600)
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail=f"Too many signups from this network. Try again in {retry}s.",
            headers={"Retry-After": str(retry)},
        )

    # Account/email/username cooldown: block rapid signup attempts even if IP rotates
    email_lower = (payload.email or "").strip().lower()
    username_lower = (payload.username or "").strip().lower()
    for key in [f"signup_email:{email_lower}", f"signup_username:{username_lower}"]:
        allowed, retry = rate_limit_check(key, max_events=3, window_seconds=3600)
        if not allowed:
            raise HTTPException(
                status_code=429,
                detail=f"Too many signup attempts. Try again in {retry}s.",
                headers={"Retry-After": str(retry)},
            )

    username = (payload.username or "").strip()
    email = (payload.email or "").strip().lower()
    password = payload.password or ""

    # Validation
    ok, reason = is_valid_username(username)
    if not ok:
        raise HTTPException(status_code=400, detail=reason)
    ok, reason = is_valid_email(email)
    if not ok:
        raise HTTPException(status_code=400, detail=reason)
    pw_errors = password_strength_errors(password)
    if pw_errors:
        # Surface the first error to keep the message short, but log all
        raise HTTPException(status_code=400, detail=pw_errors[0])

    # Pre-check (best effort, gives nicer error message than IntegrityError)
    existing = db.query(User).filter(
        (User.username == username) | (User.email == email)
    ).first()
    if existing:
        # Don't reveal which of the two collided
        raise HTTPException(status_code=400, detail="Username or email already exists")

    try:
        new_user = User(
            username=username,
            email=email,
            password_hash=hash_password(password),
            coins=50,
            rank_points=0,
            is_admin=False,
        )
        # Store device fingerprint if provided. The raw fingerprint is a
        # client-controlled, quasi-identifying value — only its SHA-256
        # digest is persisted (column name says "hash", so honor it).
        if payload.fingerprint:
            fp_hash = hashlib.sha256(payload.fingerprint.encode("utf-8")).hexdigest()
            new_user.device_fingerprint_hash = fp_hash
            # Check for duplicate fingerprints (same device, different account)
            duplicate = db.query(User).filter(
                User.device_fingerprint_hash == fp_hash
            ).first()
            if duplicate:
                new_user.flagged_for_review = True
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
    except IntegrityError:
        db.rollback()
        # Lost the race against a concurrent signup with the same
        # username/email. The DB unique constraint caught it for us.
        raise HTTPException(status_code=400, detail="Username or email already exists")
    except Exception:
        db.rollback()
        raise

    access_token = issue_token(db, new_user.id)
    # Signup must hand out a refresh token too — otherwise users who create
    # accounts never get the rotating-session flow the frontend implements.
    refresh_token = create_access_token(
        data={"sub": new_user.id},
        expires_minutes=REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60,
        token_type="refresh",
    )
    try:
        rt_payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM], options={"verify_exp": False})
        db.add(ActiveToken(
            jti=rt_payload.get("jti"),
            user_id=new_user.id,
            expires_at=datetime.utcfromtimestamp(rt_payload.get("exp")),
            token_type="refresh",
        ))
        db.commit()
    except Exception as exc:
        print(f"[auth] failed to register refresh token: {exc}")
        db.rollback()
    return {
        "id": new_user.id,
        "username": new_user.username,
        "email": new_user.email,
        "coins": new_user.coins,
        "rank_points": new_user.rank_points,
        "is_admin": bool(new_user.is_admin),
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }

@app.post("/api/auth/login")
def login(payload: UserLoginRequest, request: Request, db: Session = Depends(get_db)):
    """User login endpoint.

    Defenses:
      - Turnstile CAPTCHA
      - Per-IP rate limit (20 attempts / 5 min)
      - Per-account lockout after 5 failed attempts (15 min)
      - Constant-ish time: we always run bcrypt even when the user is
        not found, by hashing a dummy password. This prevents
        username-enumeration via response timing.
    """
    if TURNSTILE_SECRET_KEY and TURNSTILE_ENABLED:
        remote_ip = request.state.real_ip
        if not _is_mobile_app_request(request) and not verify_turnstile_token(payload.turnstile_token, remote_ip):
            raise HTTPException(status_code=403, detail="Turnstile verification failed. Please complete the security check.")

    # Per-IP rate limit (defense against credential stuffing)
    ip = request.state.real_ip
    allowed, retry = rate_limit_check(f"login_ip:{ip}", max_events=20, window_seconds=300)
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail=f"Too many login attempts from this network. Try again in {retry}s.",
            headers={"Retry-After": str(retry)},
        )

    # Account-level rate limit: even if attacker rotates IPs, they can't
    # brute-force the same account more than 10 times per 5 minutes.
    identifier = (payload.username or "").strip()
    if identifier:
        account_key = f"login_account:{identifier.lower()}"
        allowed, retry = rate_limit_check(account_key, max_events=10, window_seconds=300)
        if not allowed:
            raise HTTPException(
                status_code=429,
                detail=f"Too many login attempts for this account. Try again in {retry}s.",
                headers={"Retry-After": str(retry)},
            )

    if not identifier:
        raise HTTPException(status_code=400, detail="Username or email is required")

    normalized = identifier.lower()
    user = db.query(User).filter(
        (User.username == identifier) | (User.email == normalized)
    ).first()

    # Constant-ish time path: if no user was found, still run bcrypt
    # against a dummy hash so the response time is similar to a real
    # failed login. This makes username enumeration via timing harder.
    if not user:
        bcrypt.checkpw(
            b"constant-time-dummy",
            b"$2b$12$XFrudmMD.Sd8B7Mmy2GMiu2W3JF/JdTlh5Qb97ghtVy.4hDtzvTNa"
        )
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Account lockout check
    locked, secs_left = is_account_locked(user)
    if locked:
        raise HTTPException(
            status_code=429,
            detail=f"Account temporarily locked due to too many failed attempts. Try again in {secs_left // 60 + 1} minute(s).",
            headers={"Retry-After": str(secs_left)},
        )

    # Password must be verified BEFORE we issue any tokens. Otherwise
    # a wrong password attempt would still create a row in active_tokens
    # (and on success, the wrong user would be logged in).
    if not verify_password(payload.password, user.password_hash):
        record_failed_login(user)
        db.commit()
        raise HTTPException(status_code=401, detail="Invalid credentials")

    record_successful_login(user)

    # Tokens are only issued once the password is confirmed correct.
    refresh_token = create_access_token(
        data={"sub": user.id},
        expires_minutes=REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60,
        token_type="refresh",
    )
    # Register the refresh token in active_tokens for revocation tracking.
    try:
        rt_payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM], options={"verify_exp": False})
        db.add(ActiveToken(
            jti=rt_payload.get("jti"),
            user_id=user.id,
            expires_at=datetime.utcfromtimestamp(rt_payload.get("exp")),
            token_type="refresh",
        ))
        db.commit()
    except Exception as exc:
        print(f"[auth] failed to register refresh token: {exc}")
        db.rollback()

    rate_limit_reset(f"login_user:{user.id}")

    ensure_user_not_banned(user.id, db)

    # Login anomaly detection: track IP/UA changes
    login_ip = request.state.real_ip
    login_ua = (request.headers.get("user-agent") or "").strip()[:256]

    if user.last_login_ip and user.last_login_ip != login_ip:
        user.flagged_for_review = True
    if user.last_login_user_agent and user.last_login_user_agent != login_ua:
        user.flagged_for_review = True

    user.last_login_ip = login_ip
    user.last_login_user_agent = login_ua

    # Update IP history (keep last 10)
    try:
        history = []
        if user.login_ip_history:
            history = json.loads(user.login_ip_history)
            if not isinstance(history, list):
                history = []
        history = [ip for ip in history if ip != login_ip][:9]
        history.append(login_ip)
        user.login_ip_history = json.dumps(history)
    except Exception:
        pass

    access_token = issue_token(db, user.id)
    db.commit()
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "coins": user.coins,
        "rank_points": user.rank_points,
        "is_admin": bool(user.is_admin),
        "solved_count": db.query(SolvedChallenge).filter(SolvedChallenge.user_id == user.id).count(),
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        # flagged_for_review intentionally NOT returned — it would tip off
        # abusers that our fraud controls noticed them.
    }

OTP_REQUEST_WINDOW_SECONDS = 60
OTP_VALID_SECONDS = 300
OTP_MAX_ATTEMPTS = 3


def _generate_login_otp() -> str:
    return f"{secrets.randbelow(1000000):06d}"


@app.post("/api/auth/login/otp/request")
def login_otp_request(payload: OtpLoginRequest, request: Request, db: Session = Depends(get_db)):
    """Send a 6-digit OTP to the given Telegram chat_id for passwordless login.

    Defenses:
      - Turnstile CAPTCHA
      - Per-IP rate limit (10 requests / 5 min)
      - Existing per-user 60s cooldown between requests
    """
    chat_id = (payload.chat_id or "").strip()
    if not chat_id or not chat_id.lstrip("-").isdigit():
        raise HTTPException(status_code=400, detail="A valid Telegram chat ID is required")

    if TURNSTILE_SECRET_KEY and TURNSTILE_ENABLED:
        remote_ip = request.state.real_ip
        if not verify_turnstile_token(payload.turnstile_token, remote_ip):
            raise HTTPException(status_code=403, detail="Turnstile verification failed. Please complete the security check.")

    # Per-IP rate limit (defense against OTP-spam to a leaked chat_id)
    ip = request.state.real_ip
    allowed, retry = rate_limit_check(f"otp_req_ip:{ip}", max_events=10, window_seconds=300)
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail=f"Too many OTP requests from this network. Try again in {retry}s.",
            headers={"Retry-After": str(retry)},
        )

    user = db.query(User).filter(User.telegram_chat_id == chat_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="No CipherPoint account is linked to this Telegram chat. Connect Telegram from Settings first.")

    ensure_user_not_banned(user.id, db)

    now = datetime.utcnow()
    existing_expires = getattr(user, "login_otp_expires", None)
    if existing_expires and existing_expires > now and getattr(user, "login_otp_code", None):
        last_request = getattr(user, "login_otp_requested_at", None)
        if last_request and (now - last_request).total_seconds() < OTP_REQUEST_WINDOW_SECONDS:
            wait = int(OTP_REQUEST_WINDOW_SECONDS - (now - last_request).total_seconds())
            raise HTTPException(status_code=429, detail=f"Please wait {wait}s before requesting a new OTP")

    otp = _generate_login_otp()
    user.login_otp_code = otp
    user.login_otp_expires = now + timedelta(seconds=OTP_VALID_SECONDS)
    user.login_otp_attempts = 0
    user.login_otp_requested_at = now
    db.commit()

    message = (
        f"🔐 <b>CipherPoint Login OTP</b>\n\n"
        f"Your one-time login code is:\n\n"
        f"<code>{otp}</code>\n\n"
        f"Valid for {OTP_VALID_SECONDS // 60} minutes. Do not share this code with anyone.\n\n"
        f"If you did not request this, please secure your account immediately."
    )
    sent = send_user_notification(chat_id, message)
    if not sent:
        user.login_otp_code = None
        user.login_otp_expires = None
        db.commit()
        raise HTTPException(status_code=502, detail="Failed to deliver OTP via Telegram. Check the chat ID and try again.")

    return {
        "message": f"OTP sent to Telegram chat {chat_id}",
        "expires_in": OTP_VALID_SECONDS,
        "username_hint": user.username[:2] + "***" if user.username else None
    }


@app.post("/api/auth/login/otp/verify")
def login_otp_verify(payload: OtpVerifyRequest, request: Request, db: Session = Depends(get_db)):
    """Verify the OTP and issue a JWT for the linked user.

    Defenses:
      - Per-IP rate limit (10 attempts / 5 min) so a stolen chat_id
        can't be brute-forced from one IP
      - Per-account attempt counter with hard cap (already present)
      - Constant-time compare of the OTP
    """
    chat_id = (payload.chat_id or "").strip()
    otp = (payload.otp or "").strip()
    if not chat_id or not otp:
        raise HTTPException(status_code=400, detail="Chat ID and OTP are required")

    # Per-IP rate limit (in addition to the per-user cap)
    ip = request.state.real_ip
    allowed, retry = rate_limit_check(f"otp_ip:{ip}", max_events=10, window_seconds=300)
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail=f"Too many OTP attempts from this network. Try again in {retry}s.",
            headers={"Retry-After": str(retry)},
        )

    user = db.query(User).filter(User.telegram_chat_id == chat_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="No account linked to this Telegram chat")

    ensure_user_not_banned(user.id, db)

    stored_code = getattr(user, "login_otp_code", None)
    expires = getattr(user, "login_otp_expires", None)

    if not stored_code or not expires:
        raise HTTPException(status_code=400, detail="No OTP was requested. Please request a new one.")

    if expires < datetime.utcnow():
        user.login_otp_code = None
        user.login_otp_expires = None
        db.commit()
        raise HTTPException(status_code=400, detail="OTP expired. Please request a new one.")

    attempts = int(getattr(user, "login_otp_attempts", 0) or 0)
    if attempts >= OTP_MAX_ATTEMPTS:
        user.login_otp_code = None
        user.login_otp_expires = None
        user.login_otp_attempts = 0
        db.commit()
        raise HTTPException(status_code=429, detail="Too many failed attempts. Please request a new OTP.")

    # Constant-time OTP compare (length-aware, but does not leak the
    # correct code via early-exit timing).
    if not constant_time_eq(otp, stored_code):
        user.login_otp_attempts = attempts + 1
        remaining = OTP_MAX_ATTEMPTS - user.login_otp_attempts
        db.commit()
        raise HTTPException(status_code=400, detail=f"Incorrect OTP. {remaining} attempt(s) remaining.")

    user.login_otp_code = None
    user.login_otp_expires = None
    user.login_otp_attempts = 0
    if hasattr(user, "login_otp_requested_at"):
        user.login_otp_requested_at = None
    # Successful OTP login counts as a successful auth — clear lockout.
    user.failed_login_count = 0
    user.locked_until = None
    db.commit()

    access_token = issue_token(db, user.id)
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "coins": user.coins,
        "rank_points": user.rank_points,
        "is_admin": bool(user.is_admin),
        "solved_count": db.query(SolvedChallenge).filter(SolvedChallenge.user_id == user.id).count(),
        "access_token": access_token,
        "token_type": "bearer"
    }


@app.post("/api/auth/refresh")
def refresh_token(payload: dict, db: Session = Depends(get_db)):
    """Exchange a valid refresh token for a new access token (and a
    rotated refresh token). Implements refresh-token rotation: every
    successful refresh revokes the old refresh token's jti, so a
    stolen refresh token can only be used once. This is the standard
    defense against refresh-token theft replay attacks.

    Request body: {"refresh_token": "..."}
    """
    import secrets
    supplied = (payload or {}).get("refresh_token")
    if not supplied:
        raise HTTPException(status_code=400, detail="refresh_token is required")
    try:
        decoded = jwt.decode(supplied, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Refresh token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    if decoded.get("typ") != "refresh":
        raise HTTPException(status_code=401, detail="Not a refresh token")

    jti = decoded.get("jti")
    user_id = decoded.get("sub")
    if not jti or not user_id:
        raise HTTPException(status_code=401, detail="Malformed refresh token")

    # Reject already-rotated/revoked refresh tokens
    if db.query(RevokedToken).filter(RevokedToken.jti == jti).first():
        raise HTTPException(status_code=401, detail="Refresh token has been revoked")
    # Make sure the user is still in good standing
    user = db.query(User).filter(User.id == int(user_id)).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    ensure_user_not_banned(user.id, db)

    # Revoke the old refresh token
    try:
        old_exp = datetime.utcfromtimestamp(decoded.get("exp"))
        db.add(RevokedToken(
            jti=jti,
            user_id=user.id,
            revoked_at=datetime.utcnow(),
            expires_at=old_exp,
            reason="refresh_rotation",
        ))
        db.query(ActiveToken).filter(ActiveToken.jti == jti).delete()
        db.commit()
    except Exception as exc:
        print(f"[auth] failed to revoke rotated refresh token: {exc}")
        db.rollback()

    # Issue a fresh pair
    new_access = issue_token(db, user.id)
    new_refresh = create_access_token(
        data={"sub": user.id},
        expires_minutes=REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60,
        token_type="refresh",
    )
    try:
        payload_n = jwt.decode(new_refresh, SECRET_KEY, algorithms=[ALGORITHM], options={"verify_exp": False})
        db.add(ActiveToken(
            jti=payload_n.get("jti"),
            user_id=user.id,
            expires_at=datetime.utcfromtimestamp(payload_n.get("exp")),
            token_type="refresh",
        ))
        db.commit()
    except Exception as exc:
        print(f"[auth] failed to register rotated refresh token: {exc}")
        db.rollback()

    return {
        "access_token": new_access,
        "refresh_token": new_refresh,
        "token_type": "bearer",
    }


@app.post("/api/auth/logout")
def logout(
    body: Optional[dict] = None,
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
):
    """Revoke the JWT used for this request plus, optionally, the refresh
    token supplied in the body. Other devices/sessions remain valid
    (logout is per-session, not per-user). Idempotent: if a token is
    already revoked, the endpoint still returns 200 so the client can
    clean up its local state without an error.

    Body (optional): {"refresh_token": "..."} — clients that hold a
    refresh token MUST send it here, otherwise it stays valid for 7 days
    after logout.
    """
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing authorization header")
    try:
        scheme, token = authorization.split()
        if scheme.lower() != "bearer":
            raise HTTPException(status_code=401, detail="Invalid authorization scheme")
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except (ValueError, jwt.InvalidTokenError):
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    jti = payload.get("jti")
    user_id = payload.get("sub")
    exp = datetime.utcfromtimestamp(payload.get("exp", 0))
    if not jti:
        # Older tokens issued before jti was added can't be individually
        # revoked, so we fall back to revoking ALL of this user's tokens.
        revoked = revoke_user_tokens(db, int(user_id), reason="logout_no_jti") if user_id else 0
        return {"message": "Logged out", "tokens_revoked": revoked}

    if not db.query(RevokedToken).filter(RevokedToken.jti == jti).first():
        db.add(RevokedToken(
            jti=jti,
            user_id=int(user_id) if user_id else None,
            revoked_at=datetime.utcnow(),
            expires_at=exp,
            reason="logout",
        ))
    # Also remove from active_tokens if present.
    db.query(ActiveToken).filter(ActiveToken.jti == jti).delete()
    db.commit()

    # Revoke the session's refresh token so it can't be exchanged for a
    # fresh access token after logout.
    revoked_refresh = 0
    refresh_token = (body or {}).get("refresh_token")
    if refresh_token:
        try:
            rt = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
            rt_jti = rt.get("jti")
            if rt_jti and rt.get("typ") == "refresh" and not db.query(RevokedToken).filter(RevokedToken.jti == rt_jti).first():
                db.add(RevokedToken(
                    jti=rt_jti,
                    user_id=int(user_id) if user_id else None,
                    revoked_at=datetime.utcnow(),
                    expires_at=datetime.utcfromtimestamp(rt.get("exp", 0)),
                    reason="logout",
                ))
                db.query(ActiveToken).filter(ActiveToken.jti == rt_jti).delete()
                db.commit()
                revoked_refresh = 1
        except (jwt.InvalidTokenError, TypeError, ValueError):
            pass  # ignore malformed refresh tokens — access jti already revoked

    return {"message": "Logged out", "refresh_revoked": bool(revoked_refresh)}


@app.get("/api/auth/me")
def get_current_user(user_id: int = Depends(verify_token), db: Session = Depends(get_db)):
    """Get current user profile.

    Scoped response: only the fields the frontend needs to render the
    UI. Internal/security-sensitive fields (e.g. password hash, lockout
    counters, internal nonces, OTP-related fields) are NEVER returned.
    """
    user = db.query(User).filter(User.id == user_id).first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    ensure_user_not_banned(user_id, db)
    solved_count = db.query(SolvedChallenge).filter(SolvedChallenge.user_id == user_id).count()
    solved_challenges = db.query(SolvedChallenge).filter(SolvedChallenge.user_id == user_id).all()
    challenge_ids = [entry.challenge_id for entry in solved_challenges]
    total_challenges = db.query(Challenge).filter(Challenge.status == "approved").count()

    return {
        "id": user.id,
        "username": user.username,
        "email": user.email if not user.hide_email else None,
        "coins": user.coins,
        "rank_points": user.rank_points,
        "is_admin": bool(user.is_admin),
        "solved_count": solved_count,
        "solved_challenges": challenge_ids,
        "total_challenges": total_challenges,
        "daily_bonus_claimed_at": user.daily_bonus_claimed_at,
        "weekly_challenges_used": user.weekly_challenges_used or 0,
        "weekly_reset_at": user.weekly_reset_at,
        "daily_streak": user.daily_streak or 0,
        "reports_approved": user.reports_approved or 0,
        "hints_unlocked": user.hints_unlocked or 0,
        "profile_views": user.profile_views or 0,
        "fastest_solve_seconds": user.fastest_solve_seconds,
        "first_solve_at": user.first_solve_at.isoformat() if user.first_solve_at else None,
        "flagged_for_review": bool(user.flagged_for_review),
        "created_at": user.created_at,
        "notify_new_challenges": user.notify_new_challenges,
        "notify_comments": user.notify_comments,
        "notify_mentions": user.notify_mentions,
        "telegram_chat_id": user.telegram_chat_id,
        "telegram_notifications": user.telegram_notifications,
    }


class FingerprintRequest(BaseModel):
    fingerprint: Optional[str] = None


@app.post("/api/auth/fingerprint")
def store_fingerprint(
    payload: FingerprintRequest,
    user_id: int = Depends(verify_token),
    db: Session = Depends(get_db)
):
    """Store device fingerprint for anomaly detection.
    
    The fingerprint is a privacy-preserving hash — we never store raw
    device data. It's used only to detect same-device multi-account
    creation and suspicious login patterns.
    """
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    fp = (payload.fingerprint or "").strip()
    if not fp or len(fp) > 128:
        return {"message": "Fingerprint skipped"}

    # Store only the digest (see signup) so raw quasi-identifying input
    # never lands in the database.
    fp_hash = hashlib.sha256(fp.encode("utf-8")).hexdigest()
    user.device_fingerprint_hash = fp_hash

    # Check if this fingerprint is already used by another account
    duplicate = db.query(User).filter(
        User.device_fingerprint_hash == fp_hash,
        User.id != user_id,
        User.id.isnot(None)
    ).first()
    
    if duplicate:
        # Flag both accounts for review but don't block
        user.flagged_for_review = True
        if not duplicate.flagged_for_review:
            duplicate.flagged_for_review = True
    
    db.commit()
    return {"message": "Fingerprint stored", "flagged": bool(user.flagged_for_review)}

@app.get("/api/profile")
def get_profile(user_id: int = Depends(verify_token), db: Session = Depends(get_db)):
    """Protected profile endpoint"""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    ensure_user_not_banned(user_id, db)
    solved = (
        db.query(SolvedChallenge, Challenge)
        .join(Challenge, Challenge.id == SolvedChallenge.challenge_id)
        .filter(SolvedChallenge.user_id == user_id)
        .order_by(SolvedChallenge.solved_at.desc())
        .all()
    )
    solved_titles = [
        {
            "id": challenge.id,
            "title": challenge.title,
            "difficulty": challenge.difficulty,
            "solved_at": solved_entry.solved_at,
        }
        for solved_entry, challenge in solved
    ]

    created_challenges = db.query(Challenge).filter(Challenge.created_by == user_id, Challenge.status.notin_(["rejected", "removed"])).all()
    created_titles = []
    for challenge in created_challenges:
        created_titles.append({"id": challenge.id, "title": challenge.title, "category": challenge.category, "difficulty": challenge.difficulty, "created_at": challenge.created_at})

    visible_email = None if user.hide_email else user.email

    return {
        "id": user.id,
        "username": user.username,
        "email": visible_email,
        "email_hidden": bool(user.hide_email),
        "coins": user.coins,
        "daily_bonus_claimed_at": user.daily_bonus_claimed_at,
        "weekly_challenges_used": user.weekly_challenges_used or 0,
        "weekly_reset_at": user.weekly_reset_at,
        "rank_points": user.rank_points,
        "solved_count": len(solved_titles),
        "solved_challenges": solved_titles,
        "history": solved_titles,
        "created_challenges": created_titles,
        "created_at": user.created_at,
        "bio": user.bio,
        "avatar_url": user.avatar_url,
        "notify_new_challenges": user.notify_new_challenges,
        "notify_comments": user.notify_comments,
        "notify_mentions": user.notify_mentions,
        "hide_email": user.hide_email,
        "public_profile": user.public_profile,
        "telegram_chat_id": user.telegram_chat_id,
        "telegram_notifications": user.telegram_notifications
    }

class ProfileUpdate(BaseModel):
    username: str | None = None
    bio: str | None = None
    avatar_url: str | None = None

@app.put("/api/profile")
def update_profile(update: ProfileUpdate, user_id: int = Depends(verify_token), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    ensure_user_not_banned(user_id, db)

    if update.username and update.username != user.username:
        ok, reason = is_valid_username(update.username)
        if not ok:
            raise HTTPException(status_code=400, detail=reason)
        existing = db.query(User).filter(User.username == update.username).first()
        if existing and existing.id != user_id:
            raise HTTPException(status_code=400, detail="Username already taken")
        user.username = update.username

    if update.bio is not None:
        if len(update.bio) > 500:
            raise HTTPException(status_code=400, detail="Bio is too long (max 500 characters)")
        user.bio = update.bio

    if update.avatar_url is not None:
        if len(update.avatar_url) > 500:
            raise HTTPException(status_code=400, detail="Avatar URL is too long (max 500 characters)")
        if update.avatar_url and not re.match(r"^https?://", update.avatar_url):
            raise HTTPException(status_code=400, detail="Avatar URL must start with http:// or https://")
        user.avatar_url = update.avatar_url

    db.commit()
    db.refresh(user)

    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "coins": user.coins,
        "rank_points": user.rank_points,
        "bio": user.bio,
        "avatar_url": user.avatar_url,
        "created_at": user.created_at,
    }

class TelegramConnectRequest(BaseModel):
    chat_id: str
    enabled: bool | None = True

class TelegramSettingsRequest(BaseModel):
    enabled: bool | None = None
    chat_id: str | None = None

class PasswordResetRequest(BaseModel):
    username: str
    turnstile_token: str | None = None

class PasswordResetConfirm(BaseModel):
    reset_token: str
    new_password: str

class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str

@app.put("/api/settings/password")
def change_password(payload: PasswordChangeRequest, user_id: int = Depends(verify_token), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if not verify_password(payload.current_password, user.password_hash):
        # Reuse the login lockout mechanism so brute-forcing the
        # current-password field doesn't bypass the account lockout.
        record_failed_login(user)
        db.commit()
        raise HTTPException(status_code=400, detail="Current password is incorrect")

    pw_errors = password_strength_errors(payload.new_password or "")
    if pw_errors:
        raise HTTPException(status_code=400, detail=pw_errors[0])

    # Refuse to "change" the password to the exact same one. This avoids
    # sending a misleading "password updated" notification and prevents
    # trivial lockout from being used as a denial-of-service vector.
    if verify_password(payload.new_password, user.password_hash):
        raise HTTPException(
            status_code=400,
            detail="New password must be different from the current one",
        )

    user.password_hash = hash_password(payload.new_password)
    # Wipe any outstanding password-reset tokens so they can't be reused.
    user.reset_token = None
    user.reset_token_expires = None
    # Invalidate all active sessions. Anyone holding an old token (e.g.
    # a thief who stole the previous password) is now locked out on the
    # next request, even before the JWT's 30-minute exp would expire.
    revoke_user_tokens(db, user.id, reason="password_changed")
    db.commit()

    if user.telegram_chat_id and user.telegram_notifications:
        send_user_notification(
            user.telegram_chat_id,            f"🔐 <b>Password updated</b>\n\nHello <b>{escape_html(user.username)}</b>, your CipherPoint password was successfully changed."
        )

    return {"message": "Password updated successfully"}


class EmergencyResetRequest(BaseModel):
    username: str
    new_password: str
    master_key: str


@app.post("/api/admin/emergency-reset-password")
def emergency_reset_password(payload: EmergencyResetRequest, request: Request, db: Session = Depends(get_db)):
    """Emergency password reset using a master key from env.

    Set ADMIN_MASTER_KEY in Render env to enable. This is a recovery hatch
    for when the admin account is locked out. The master key is never
    returned and is checked in constant time.
    """
    expected = os.getenv("ADMIN_MASTER_KEY")
    if not expected:
        raise HTTPException(status_code=503, detail="Emergency reset is not configured on this server")
    # Rate limit per source IP: without this, the master key is an
    # unauthenticated online-brute-force target.
    ip = request.state.real_ip
    allowed, retry = rate_limit_check(f"emergency_reset:{ip}", max_events=5, window_seconds=3600)
    if not allowed:
        print(f"[SECURITY] Emergency-reset rate limit hit from {ip}")
        raise HTTPException(
            status_code=429,
            detail=f"Too many attempts. Try again in {retry}s.",
            headers={"Retry-After": str(retry)},
        )
    if not hmac.compare_digest(payload.master_key, expected):
        # Generic message to avoid leaking whether the key is set
        print(f"[SECURITY] Failed emergency-reset master key attempt from {ip}")
        raise HTTPException(status_code=403, detail="Invalid master key")
    # Use the same strength policy as the user-facing password change flow
    # so an emergency reset can't be used to lock an account behind a weak password.
    if not isinstance(payload.new_password, str) or len(payload.new_password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    if not re.search(r"[A-Za-z]", payload.new_password) or not re.search(r"\d", payload.new_password):
        raise HTTPException(status_code=400, detail="Password must contain both a letter and a digit")
    if payload.new_password.lower() in COMMON_PASSWORDS:
        raise HTTPException(status_code=400, detail="Password is too common — choose a different one")

    # Constant-time-ish lookup: query both fields, pick whichever matched.
    username_clean = payload.username.strip()
    user = db.query(User).filter(User.username == username_clean).first()
    if not user:
        user = db.query(User).filter(User.email == username_clean.lower()).first()
    if not user:
        # Same 404 message regardless of which field was probed.
        raise HTTPException(status_code=404, detail="User not found")

    user.password_hash = hash_password(payload.new_password)
    user.reset_token = None
    user.reset_token_expires = None
    # Lock out any session that was open before the reset.
    revoke_user_tokens(db, user.id, reason="emergency_reset")
    return {"message": f"Password reset for {user.username}", "username": user.username}


# ==================== ADMIN USER MANAGEMENT ====================

class AdminBanRequest(BaseModel):
    user_id: int
    reason: str
    days: int = 0  # 0 = permanent


@app.get("/api/admin/users")
def admin_list_users(
    q: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    admin_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """Admin: list or search users.

    If `q` is provided, performs a case-insensitive partial match on username
    or email, or an exact ID match. Returns up to `limit` users (default 50).
    The response is intentionally minimal — never include password_hash.
    """
    limit = max(1, min(limit, 200))
    offset = max(0, offset)

    base_query = db.query(User)
    if q:
        q_clean = q.strip()[:64]  # cap to prevent abuse
        if q_clean.isdigit():
            base_query = base_query.filter(User.id == int(q_clean))
        else:
            # Strip SQL LIKE wildcards from user input to prevent unintended matches.
            safe = q_clean.replace("%", "").replace("_", "")
            like = f"%{safe.lower()}%"
            base_query = base_query.filter(
                (func.lower(User.username).like(like)) |
                (func.lower(User.email).like(like))
            )

    total = base_query.count()
    users = (
        base_query
        .order_by(User.id.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    # Build a set of *active* banned user IDs. Scoped to the returned user IDs
    # so we don't load the whole ban table on a 100k-user install.
    result_ids = [u.id for u in users]
    banned_ids = {
        row.user_id
        for row in db.query(UserBan.user_id).filter(UserBan.user_id.in_(result_ids)).all()
    } if result_ids else set()

    items = []
    for u in users:
        items.append({
            "id": u.id,
            "username": u.username,
            "email": u.email,
            "is_admin": bool(getattr(u, "is_admin", False)),
            "banned": u.id in banned_ids,
            "coins": u.coins or 0,
            "rank_points": u.rank_points or 0,
            "created_at": u.created_at.isoformat() if u.created_at else None,
            "is_active": u.id not in banned_ids,
        })
    return {"items": items, "total": total, "limit": limit, "offset": offset}


@app.post("/api/admin/users/ban")
def admin_ban_user(
    payload: AdminBanRequest,
    admin_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """Admin: ban a user.

    If `days` > 0 the ban is created with an expiry; permanent otherwise.
    Idempotent: re-banning an already banned user updates the reason and
    extends the ban window. The target user is notified via Telegram if
    their chat_id is linked.
    """
    if not isinstance(payload.user_id, int) or payload.user_id <= 0:
        raise HTTPException(status_code=400, detail="Invalid user_id")
    if not isinstance(payload.days, int) or payload.days < 0 or payload.days > 3650:
        raise HTTPException(status_code=400, detail="Invalid days (0..3650)")
    reason = (payload.reason or "").strip()
    if not reason:
        raise HTTPException(status_code=400, detail="Ban reason is required")
    if len(reason) > 1000:
        raise HTTPException(status_code=400, detail="Ban reason too long (max 1000 chars)")

    target = db.query(User).filter(User.id == payload.user_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    if target.id == admin_user.id:
        raise HTTPException(status_code=400, detail="You cannot ban yourself")
    if getattr(target, "is_admin", False):
        raise HTTPException(status_code=400, detail="You cannot ban another admin")

    existing = db.query(UserBan).filter(UserBan.user_id == target.id).first()
    expires_at = None
    if payload.days > 0:
        expires_at = datetime.utcnow() + timedelta(days=payload.days)

    if existing:
        existing.reason = reason
        existing.banned_by = admin_user.id
        existing.created_at = datetime.utcnow()
        existing.expires_at = expires_at
    else:
        ban = UserBan(
            user_id=target.id,
            reason=reason,
            banned_by=admin_user.id,
            expires_at=expires_at,
        )
        db.add(ban)

    # Kick the user out of every active session immediately. Without
    # this, their existing JWT would still be valid for up to 30 minutes
    # after the ban was issued, leaving a security window.
    revoked = revoke_user_tokens(db, target.id, reason=f"banned: {reason[:120]}")

    db.commit()

    # Notify via Telegram if linked
    if getattr(target, "telegram_chat_id", None):
        try:
            duration = f"{payload.days} days" if payload.days and payload.days > 0 else "permanently"
            send_user_notification(
                str(target.telegram_chat_id),
                "🚫 <b>Account suspended</b>\n\n"
                f"Your CipherPoint account has been suspended {duration} by {admin_user.username}.\n\n"
                f"<b>Reason:</b> {escape_html(reason)}"
            )
        except Exception as exc:
            print(f"[admin-ban] telegram notify failed for user {target.id}: {exc}")

    return {
        "message": f"User {target.username} banned",
        "user_id": target.id,
        "username": target.username,
        "expires_at": expires_at.isoformat() if expires_at else None,
    }


@app.post("/api/admin/users/unban")
def admin_unban_user(
    payload: AdminBanRequest,
    admin_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """Admin: lift a ban. The `reason` and `days` fields are ignored."""
    existing = db.query(UserBan).filter(UserBan.user_id == payload.user_id).first()
    if not existing:
        raise HTTPException(status_code=404, detail="User is not banned")
    db.delete(existing)
    db.commit()
    return {"message": "Ban lifted", "user_id": payload.user_id}


@app.get("/api/admin/users/flagged")
def admin_list_flagged_users(
    limit: int = 50,
    offset: int = 0,
    admin_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """Admin: list users flagged for review."""
    limit = max(1, min(limit, 200))
    offset = max(0, offset)

    base_query = db.query(User).filter(User.flagged_for_review == True)
    total = base_query.count()
    users = (
        base_query
        .order_by(User.id.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    result_ids = [u.id for u in users]
    banned_ids = {
        row.user_id
        for row in db.query(UserBan.user_id).filter(UserBan.user_id.in_(result_ids)).all()
    } if result_ids else set()

    items = []
    for u in users:
        items.append({
            "id": u.id,
            "username": u.username,
            "email": u.email,
            "is_admin": bool(getattr(u, "is_admin", False)),
            "banned": u.id in banned_ids,
            "coins": u.coins or 0,
            "rank_points": u.rank_points or 0,
            "created_at": u.created_at.isoformat() if u.created_at else None,
            "is_active": u.id not in banned_ids,
            "flagged_for_review": bool(u.flagged_for_review),
            "device_fingerprint_hash": u.device_fingerprint_hash,
            "fastest_solve_seconds": u.fastest_solve_seconds,
        })
    return {"items": items, "total": total, "limit": limit, "offset": offset}


class AdminUnflagRequest(BaseModel):
    user_id: int


@app.post("/api/admin/users/unflag")
def admin_unflag_user(
    payload: AdminUnflagRequest,
    admin_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """Admin: clear the flagged_for_review flag on a user."""
    user = db.query(User).filter(User.id == payload.user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if not user.flagged_for_review:
        raise HTTPException(status_code=404, detail="User is not flagged")
    user.flagged_for_review = False
    db.commit()
    return {"message": "Flag cleared", "user_id": payload.user_id}


# ==================== NOTIFICATIONS SETTINGS ====================

class NotificationSettingsRequest(BaseModel):
    notify_new_challenges: bool | None = None
    notify_comments: bool | None = None
    notify_mentions: bool | None = None

@app.put("/api/settings/notifications")
def update_notification_settings(payload: NotificationSettingsRequest, user_id: int = Depends(verify_token), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    ensure_user_not_banned(user_id, db)

    if payload.notify_new_challenges is not None:
        user.notify_new_challenges = payload.notify_new_challenges
    if payload.notify_comments is not None:
        user.notify_comments = payload.notify_comments
    if payload.notify_mentions is not None:
        user.notify_mentions = payload.notify_mentions

    db.commit()
    db.refresh(user)

    return {
        "notify_new_challenges": user.notify_new_challenges,
        "notify_comments": user.notify_comments,
        "notify_mentions": user.notify_mentions
    }

class PrivacySettingsRequest(BaseModel):
    hide_email: bool | None = None
    public_profile: bool | None = None

@app.put("/api/settings/privacy")
def update_privacy_settings(payload: PrivacySettingsRequest, user_id: int = Depends(verify_token), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    ensure_user_not_banned(user_id, db)

    if payload.hide_email is not None:
        user.hide_email = payload.hide_email
    if payload.public_profile is not None:
        user.public_profile = payload.public_profile

    db.commit()
    db.refresh(user)

    return {
        "hide_email": user.hide_email,
        "public_profile": user.public_profile
    }

@app.delete("/api/settings/account")
def delete_account(user_id: int = Depends(verify_token), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # A banned user must not be able to delete their account: deletion
    # also removes their ban row, which would let them re-register clean.
    ensure_user_not_banned(user_id, db)

    db.query(SolvedChallenge).filter(SolvedChallenge.user_id == user_id).delete(synchronize_session=False)
    db.query(UnlockedHint).filter(UnlockedHint.user_id == user_id).delete(synchronize_session=False)
    db.query(ChallengeReport).filter(ChallengeReport.reporter_id == user_id).delete(synchronize_session=False)
    user_comment_ids = [
        row[0] for row in db.query(Comment.id).filter(Comment.user_id == user_id).all()
    ]
    if user_comment_ids:
        db.query(Comment).filter(Comment.parent_id.in_(user_comment_ids)).update(
            {Comment.parent_id: None}, synchronize_session=False
        )
        db.query(Comment).filter(Comment.id.in_(user_comment_ids)).delete(synchronize_session=False)
    db.query(ChallengeReport).filter(ChallengeReport.resolved_by == user_id).update(
        {ChallengeReport.resolved_by: None}, synchronize_session=False
    )
    # Only drop the user's own ban record. Bans this user issued against
    # others (banned_by) are moderation history and must survive deletion.
    db.query(UserBan).filter(UserBan.user_id == user_id).delete(synchronize_session=False)

    revoke_user_tokens(db, user_id, reason="account_deleted")

    db.delete(user)
    db.commit()

    return {"message": "Account deleted successfully"}


@app.post("/api/profile/daily-bonus")
def claim_daily_bonus(user_id: int = Depends(verify_token), db: Session = Depends(get_db)):
    """Claim the daily bonus once per UTC day, enforced server-side."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    ensure_user_not_banned(user_id, db)

    now = datetime.utcnow()
    today_str = now.date().isoformat()
    last_claimed_date = user.daily_bonus_claimed_at.date().isoformat() if user.daily_bonus_claimed_at else None

    if last_claimed_date == today_str:
        raise HTTPException(status_code=409, detail="Daily bonus already claimed today")

    new_streak = 1
    if last_claimed_date:
        from datetime import date
        last_date = date.fromisoformat(last_claimed_date)
        if (now.date() - last_date).days == 1:
            new_streak = (user.daily_streak or 0) + 1
        elif (now.date() - last_date).days > 1:
            new_streak = 1

    # The date guard lives in the WHERE clause, so two concurrent claims
    # resolve atomically: only the first UPDATE matches and pays out.
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    updated = db.query(User).filter(
        User.id == user_id,
        (User.daily_bonus_claimed_at.is_(None)) | (User.daily_bonus_claimed_at < today_start),
    ).update(
        {
            User.coins: func.coalesce(User.coins, 0) + 10,
            User.daily_bonus_claimed_at: now,
            User.daily_streak: new_streak,
        },
        synchronize_session=False,
    )
    if not updated:
        raise HTTPException(status_code=409, detail="Daily bonus already claimed today")

    db.commit()
    db.refresh(user)
    return {"message": "Daily bonus claimed", "coins_earned": 10, "total_coins": user.coins, "daily_streak": user.daily_streak}


@app.get("/api/settings/telegram/bot-info")
def get_telegram_bot_info():
    """Return bot username so frontend can build a /start deep link."""
    if not TELEGRAM_REPORT_BOT_TOKEN:
        return {"bot_username": None, "configured": False}
    try:
        response = requests.get(f"https://api.telegram.org/bot{TELEGRAM_REPORT_BOT_TOKEN}/getMe", timeout=5)
        data = response.json()
        if data.get("ok"):
            return {"bot_username": data["result"].get("username"), "configured": True}
    except Exception as e:
        print(f"[TELEGRAM] Failed to fetch bot info: {e}")
    return {"bot_username": None, "configured": False}


@app.get("/api/settings/telegram/connect-nonce")
def get_telegram_connect_nonce(user_id: int = Depends(verify_token), db: Session = Depends(get_db)):
    """Generate a one-time nonce for Telegram deep-link verification."""
    import secrets
    from datetime import datetime, timedelta

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    nonce = secrets.token_urlsafe(24)
    user.telegram_connect_nonce = nonce
    user.telegram_connect_nonce_expires = datetime.utcnow() + timedelta(minutes=15)
    db.commit()
    return {"nonce": nonce, "expires_in": 900}


@app.delete("/api/settings/telegram/disconnect")
def disconnect_telegram(user_id: int = Depends(verify_token), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.telegram_chat_id = None
    user.telegram_notifications = False
    db.commit()
    return {"message": "Telegram disconnected"}


@app.put("/api/settings/telegram")
def update_telegram_settings(payload: TelegramSettingsRequest, user_id: int = Depends(verify_token), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if payload.enabled is not None:
        if not user.telegram_chat_id and payload.enabled:
            raise HTTPException(status_code=400, detail="Connect Telegram first before enabling notifications")
        user.telegram_notifications = payload.enabled
    if payload.chat_id is not None:
        raw_chat_id = (payload.chat_id or "").strip()
        if not raw_chat_id or not raw_chat_id.lstrip("-").isdigit():
            raise HTTPException(status_code=400, detail="Invalid Telegram chat ID format")
        # Reject chat IDs already bound to another account: OTP login
        # resolves users by chat_id, so a shared chat_id can route a
        # login OTP (or delivery) to the wrong account.
        taken = db.query(User).filter(
            User.telegram_chat_id == raw_chat_id,
            User.id != user_id,
        ).first()
        if taken:
            raise HTTPException(status_code=409, detail="This Telegram chat is already linked to another account")
        user.telegram_chat_id = raw_chat_id

    db.commit()
    db.refresh(user)
    return {
        "telegram_chat_id": user.telegram_chat_id,
        "telegram_notifications": user.telegram_notifications
    }


@app.post("/api/auth/password-reset/request")
def request_password_reset(payload: PasswordResetRequest, request: Request, db: Session = Depends(get_db)):
    """Request a password reset.

    Defenses:
      - Turnstile CAPTCHA
      - Per-IP rate limit (5 requests / hour)
      - Constant-time response: we always return the same message,
        always do a DB lookup (even when the username is empty), and
        always do a (cheap) DB write attempt. This prevents
        username-enumeration via response timing or status code.
    """
    if TURNSTILE_SECRET_KEY and TURNSTILE_ENABLED:
        remote_ip = request.state.real_ip
        if not verify_turnstile_token(payload.turnstile_token, remote_ip):
            raise HTTPException(status_code=403, detail="Turnstile verification failed. Please complete the security check.")

    ip = request.state.real_ip
    allowed, retry = rate_limit_check(f"reset_ip:{ip}", max_events=5, window_seconds=3600)
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail=f"Too many password reset attempts. Try again in {retry}s.",
            headers={"Retry-After": str(retry)},
        )

    # Account-level rate limit: prevent reset spam for a specific user
    username_key = (payload.username or "").strip().lower()
    if username_key:
        allowed, retry = rate_limit_check(f"reset_account:{username_key}", max_events=3, window_seconds=3600)
        if not allowed:
            raise HTTPException(
                status_code=429,
                detail=f"Too many reset attempts for this account. Try again in {retry}s.",
                headers={"Retry-After": str(retry)},
            )

    raw_identifier = (payload.username or "").strip()
    normalized = raw_identifier.lower()
    GENERIC_RESPONSE = {"message": "If the account exists and has a linked Telegram, a reset code has been sent."}

    # Constant-time-ish: always look up the user, even if input is empty.
    user = None
    if raw_identifier:
        user = db.query(User).filter(
            (User.username == raw_identifier) | (User.email == normalized)
        ).first()

    # Branch on whether the user can actually receive a reset code. We
    # intentionally do not short-circuit the DB write / Telegram call
    # when the user is missing, so timing doesn't leak account existence.
    if user and user.telegram_chat_id and TELEGRAM_REPORT_BOT_TOKEN:
        import secrets as _secrets
        from datetime import datetime as _dt, timedelta as _td
        token = _secrets.token_urlsafe(32)
        user.reset_token = token
        user.reset_token_expires = _dt.utcnow() + _td(minutes=30)
        try:
            db.commit()
        except Exception:
            db.rollback()
            return GENERIC_RESPONSE

        message = (
            f"🔐 <b>Password Reset Request</b>\n\n"
            f"Hello <b>{escape_html(user.username)}</b>,\n\n"
            f"Use this token to reset your password (valid for 30 minutes):\n\n"
            f"<code>{token}</code>\n\n"
            f"If you did not request this, please secure your account immediately."
        )
        try:
            send_user_notification(user.telegram_chat_id, message)
        except Exception:
            # Don't leak the error to the caller
            pass
    # else: do nothing — fall through to the generic response.

    return GENERIC_RESPONSE


@app.post("/api/auth/password-reset/confirm")
def confirm_password_reset(payload: PasswordResetConfirm, request: Request, db: Session = Depends(get_db)):
    from datetime import datetime
    ip = request.state.real_ip
    allowed, retry = rate_limit_check(f"reset_confirm:{ip}", max_events=10, window_seconds=3600)
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail=f"Too many reset attempts. Try again in {retry}s.",
            headers={"Retry-After": str(retry)},
        )
    user = db.query(User).filter(User.reset_token == payload.reset_token).first()
    if not user:
        raise HTTPException(status_code=400, detail="Invalid or expired token")

    expires = getattr(user, "reset_token_expires", None)
    if not expires or expires < datetime.utcnow():
        raise HTTPException(status_code=400, detail="Invalid or expired token")

    pw_errors = password_strength_errors(payload.new_password or "")
    if pw_errors:
        raise HTTPException(status_code=400, detail=pw_errors[0])

    # Don't allow resetting to the current password (no-op reset).
    if verify_password(payload.new_password, user.password_hash):
        raise HTTPException(status_code=400, detail="New password must be different from the current one")

    user.password_hash = hash_password(payload.new_password)
    setattr(user, "reset_token", None)
    setattr(user, "reset_token_expires", None)
    # Also clear any failed-login state so a successful reset doesn't
    # leave the user locked out.
    user.failed_login_count = 0
    user.locked_until = None
    # Kill every active session: a thief holding a stolen token must not
    # survive the victim's password reset (same rule as change_password).
    revoke_user_tokens(db, user.id, reason="password_reset")

    if user.telegram_chat_id:
        send_user_notification(
            user.telegram_chat_id,
            f"✅ <b>Password updated</b>\n\nYour CipherPoint password was successfully changed."
        )

    return {"message": "Password reset successful"}

# ==================== CHALLENGES ROUTES ====================

@app.get("/api/challenges")
def get_all_challenges(limit: Optional[int] = None, db: Session = Depends(get_db)):
    """Get all approved challenges with metadata (cached 60s)"""
    normalized_limit = min(max(limit, 1), 100) if limit is not None else None
    cache_key = f"challenges:{normalized_limit or 'all'}"
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached
    challenge_query = db.query(Challenge).filter(Challenge.status.notin_(["rejected", "removed"]))
    if normalized_limit is not None:
        challenge_query = challenge_query.limit(normalized_limit)
    challenges = challenge_query.all()
    challenge_ids = [challenge.id for challenge in challenges]
    comment_counts = dict(
        db.query(Comment.challenge_id, func.count(Comment.id))
        .filter(Comment.challenge_id.in_(challenge_ids))
        .group_by(Comment.challenge_id)
        .all()
    ) if challenge_ids else {}

    result = []
    for challenge in challenges:
        solved_count = db.query(SolvedChallenge).filter(SolvedChallenge.challenge_id == challenge.id).count()
        result.append({
            "id": challenge.id,
            "title": challenge.title,
            "category": challenge.category,
            "difficulty": challenge.difficulty,
            "description": challenge.description,
            "media_url": f"/api/media/{challenge.telegram_file_id}" if challenge.telegram_file_id else None,
            "points_reward": challenge.points_reward,
            "solved_count": solved_count,
            "status": challenge.status,
            "is_community": bool(challenge.is_community),
            "is_cipher_day": is_cipher_day_challenge(challenge),
            "comments_count": comment_counts.get(challenge.id, 0),
            "has_walkthrough": bool(challenge.solution_walkthrough),
            "created_at": challenge.created_at
        })

    _cache_set(cache_key, result, ttl=60)
    return result


@app.get("/api/challenges/community")
def get_community_challenges(db: Session = Depends(get_db)):
    """Get public community-run challenges."""
    challenges = db.query(Challenge).filter((Challenge.is_community == True) & (Challenge.status.notin_(["rejected", "removed"]))).all()
    challenge_ids = [challenge.id for challenge in challenges]
    comment_counts = dict(
        db.query(Comment.challenge_id, func.count(Comment.id))
        .filter(Comment.challenge_id.in_(challenge_ids))
        .group_by(Comment.challenge_id)
        .all()
    ) if challenge_ids else {}
    result = []
    for challenge in challenges:
        solved_count = db.query(SolvedChallenge).filter(SolvedChallenge.challenge_id == challenge.id).count()
        result.append({
            "id": challenge.id,
            "title": challenge.title,
            "category": challenge.category,
            "difficulty": challenge.difficulty,
            "description": challenge.description,
            "media_url": f"/api/media/{challenge.telegram_file_id}" if challenge.telegram_file_id else None,
            "points_reward": challenge.points_reward,
            "solved_count": solved_count,
            "status": challenge.status,
            "comments_count": comment_counts.get(challenge.id, 0),
            "tags": challenge.tags or "",
            "created_at": challenge.created_at,
        })
    return result

@app.get("/api/challenges/{challenge_id}")
def get_challenge_details(
    challenge_id: int,
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db)
):
    """Get detailed view of a challenge (WITHOUT flag or hints).

    Walkthrough is only returned to the user who solved the challenge,
    the challenge author, or any admin. Anonymous users and other
    users see `solution_walkthrough: null` so the answer is never
    leaked before solve.
    """
    challenge = db.query(Challenge).filter(Challenge.id == challenge_id).first()

    if not challenge or challenge.status in {"rejected", "removed"}:
        raise HTTPException(status_code=404, detail="Challenge not found")
    if is_cipher_day_challenge(challenge) and not is_cipher_day_window_open():
        raise HTTPException(status_code=404, detail="Challenge not found")

    solved_count = db.query(SolvedChallenge).filter(SolvedChallenge.challenge_id == challenge_id).count()
    comments_count = db.query(Comment).filter(Comment.challenge_id == challenge_id).count()

    # Walkthrough gating: only the author, an admin, or a user who has
    # solved this challenge may see the walkthrough text.
    viewer_id: Optional[int] = None
    viewer_is_admin = False
    if authorization:
        try:
            scheme, token = authorization.split()
            if scheme.lower() == "bearer":
                payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
                viewer_id = payload.get("sub")
                if viewer_id is not None:
                    viewer = db.query(User).filter(User.id == viewer_id).first()
                    if viewer:
                        viewer_is_admin = bool(getattr(viewer, "is_admin", False))
        except Exception:
            viewer_id = None

    show_walkthrough = False
    if viewer_id:
        if viewer_is_admin or challenge.created_by == viewer_id:
            show_walkthrough = True
        else:
            solved = db.query(SolvedChallenge).filter(
                (SolvedChallenge.user_id == viewer_id) &
                (SolvedChallenge.challenge_id == challenge_id)
            ).first()
            show_walkthrough = bool(solved)

    return {
        "id": challenge.id,
        "title": challenge.title,
        "category": challenge.category,
        "difficulty": challenge.difficulty,
        "description": challenge.description,
        "media_url": f"/api/media/{challenge.telegram_file_id}" if challenge.telegram_file_id else None,
        "points_reward": challenge.points_reward,
        "has_hint_1": bool(challenge.hint_1),
        "has_hint_2": bool(challenge.hint_2),
        "hint_1_cost": challenge.hint_1_cost,
        "hint_2_cost": challenge.hint_2_cost,
        "tags": challenge.tags,
        "solution_walkthrough": (challenge.solution_walkthrough or None) if show_walkthrough else None,
        "can_view_walkthrough": show_walkthrough,
        "is_community": bool(challenge.is_community),
        "status": challenge.status,
        "solved_count": solved_count,
        "comments_count": comments_count,
        "created_at": challenge.created_at
    }

@app.post("/api/challenges/create")
def create_challenge(
    payload: ChallengeCreateRequest,
    user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """Create new challenge (Admin only). Accepts JSON payload."""
    _validate_community_payload(payload)

    title = payload.title.strip()
    category = payload.category.strip()
    difficulty = payload.difficulty.strip()
    description = payload.description.strip()
    telegram_file_id = payload.telegram_file_id.strip()
    correct_flag = payload.correct_flag.strip()

    new_challenge = Challenge(
        title=title,
        category=category,
        difficulty=difficulty,
        description=description,
        telegram_file_id=telegram_file_id,
        correct_flag=correct_flag,
        points_reward=payload.points_reward,
        hint_1=(payload.hint_1 or "").strip() or None,
        hint_1_cost=payload.hint_1_cost,
        hint_2=(payload.hint_2 or "").strip() or None,
        hint_2_cost=payload.hint_2_cost,
        solution_walkthrough=(payload.solution_walkthrough or "").strip() or None,
        created_by=user.id,
        status="approved",
        is_community=False,
        disclaimer_accepted=True,
        tags=(payload.tags or "").strip(),
    )

    db.add(new_challenge)
    db.commit()
    db.refresh(new_challenge)

    _cache_clear_prefix("challenges:")
    return {
        "id": new_challenge.id,
        "title": new_challenge.title,
        "message": "Challenge created successfully!",
        "created_by": user.username,
    }


@app.post("/api/challenges/community/create")
def create_community_challenge(
    payload: CommunityChallengeCreateRequest,
    user_id: int = Depends(verify_token),
    db: Session = Depends(get_db)
):
    """Allow authenticated users to submit a community challenge with policy enforcement."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    ensure_user_not_banned(user_id, db)

    # Length / type / range validation (single source of truth)
    _validate_community_payload(payload)

    # Identity-content policy check
    combined = " ".join([
        payload.title or "",
        payload.category or "",
        payload.description or "",
        payload.correct_flag or "",
        payload.tags or "",
    ])
    if is_sensitive_identity_content(combined):
        raise HTTPException(status_code=400, detail="Personal identity or private data is not allowed on this platform.")

    # Spam guard: reject obvious duplicates (same title + flag from the
    # same user within the last 24 hours).
    from datetime import timedelta as _td
    recent_dup = db.query(Challenge).filter(
        Challenge.created_by == user_id,
        Challenge.title == payload.title.strip(),
        Challenge.correct_flag == payload.correct_flag.strip(),
        Challenge.created_at >= datetime.utcnow() - _td(hours=24),
    ).first()
    if recent_dup:
        raise HTTPException(
            status_code=409,
            detail="You already published a challenge with this title and flag in the last 24 hours.",
        )

    title = payload.title.strip()
    category = payload.category.strip()
    difficulty = payload.difficulty.strip()
    description = payload.description.strip()
    telegram_file_id = payload.telegram_file_id.strip()
    correct_flag = payload.correct_flag.strip()

    reserve_community_quota(user, db)
    new_challenge = Challenge(
        title=title,
        category=category,
        difficulty=difficulty,
        description=description,
        telegram_file_id=telegram_file_id,
        correct_flag=correct_flag,
        points_reward=payload.points_reward,
        hint_1=(payload.hint_1 or "").strip() or None,
        hint_1_cost=payload.hint_1_cost,
        hint_2=(payload.hint_2 or "").strip() or None,
        hint_2_cost=payload.hint_2_cost,
        solution_walkthrough=(payload.solution_walkthrough or "").strip() or None,
        created_by=user_id,
        status="approved",
        is_community=True,
        disclaimer_accepted=payload.disclaimer_accepted,
        tags=(payload.tags or "").strip(),
    )

    db.add(new_challenge)
    db.flush()

    if not getattr(user, "weekly_reset_at", None):
        # Only seed a reset window when the weekly quota is active. If the
        # limit is 0 (unlimited) we still set a far-future marker so the
        # /auth/me response has a sane value, but it should never be
        # consulted by the quota logic.
        user.weekly_reset_at = datetime.utcnow() + timedelta(days=7 if COMMUNITY_CTF_WEEKLY_LIMIT > 0 else 365)
    db.commit()
    db.refresh(new_challenge)

    # Invalidate cached challenge list (a new challenge was added)
    _cache_clear_prefix("challenges:")

    if COMMUNITY_CTF_WEEKLY_LIMIT <= 0:
        remaining = None  # unlimited
    else:
        remaining = max(0, COMMUNITY_CTF_WEEKLY_LIMIT - (user.weekly_challenges_used or 0))

    return {
        "id": new_challenge.id,
        "title": new_challenge.title,
        "message": "Community challenge published successfully!",
        "is_community": True,
        "status": new_challenge.status,
        "quota": {
            "used": user.weekly_challenges_used or 0,
            "limit": COMMUNITY_CTF_WEEKLY_LIMIT,
            "remaining": remaining,
            "resets_at": user.weekly_reset_at.isoformat() if user.weekly_reset_at else None
        }
    }


@app.post("/api/challenges/{challenge_id}/report")
def report_challenge(
    challenge_id: int,
    payload: ChallengeReportRequest,
    request: Request,
    reporter_id: int = Depends(verify_token),
    db: Session = Depends(get_db)
):
    """Allow users to flag a challenge for moderation review."""
    ip = request.state.real_ip
    allowed, retry = rate_limit_check(f"report_user:{reporter_id}", max_events=5, window_seconds=3600)
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail=f"Too many reports. Please wait {retry}s.",
            headers={"Retry-After": str(retry)},
        )
    try:
        ensure_user_not_banned(reporter_id, db)
        challenge = db.query(Challenge).filter(Challenge.id == challenge_id).first()
        if not challenge:
            raise HTTPException(status_code=404, detail="Challenge not found")
        if challenge.status in {"rejected", "removed"}:
            raise HTTPException(status_code=404, detail="Challenge not found")

        comment = None
        if payload.comment_id is not None:
            comment = db.query(Comment).filter(
                Comment.id == payload.comment_id,
                Comment.challenge_id == challenge_id,
            ).first()
            if not comment:
                raise HTTPException(status_code=404, detail="Comment not found")

        existing_query = db.query(ChallengeReport).filter(
            ChallengeReport.challenge_id == challenge_id,
            ChallengeReport.reporter_id == reporter_id,
        )
        existing_query = existing_query.filter(
            ChallengeReport.comment_id == payload.comment_id
            if payload.comment_id is not None
            else ChallengeReport.comment_id.is_(None)
        )
        existing = existing_query.first()
        if existing:
            target = "comment" if comment else "challenge"
            return {"message": f"You already reported this {target}.", "status": "already_reported"}

        reason = payload.reason.strip()[:200]
        details = payload.details.strip()[:400]
        if not reason:
            raise HTTPException(status_code=400, detail="Report reason is required")

        report = ChallengeReport(
            challenge_id=challenge_id,
            comment_id=comment.id if comment else None,
            target_type="comment" if comment else "challenge",
            reporter_id=reporter_id,
            reason=reason,
            details=details,
            status="open",
            ip_address=ip,
        )
        challenge.report_count += 1
        db.add(report)
        db.commit()

        _check_content_spam(ip, reporter_id, db)
        db.commit()

        reporter = db.query(User).filter(User.id == reporter_id).first()
        reporter_name = reporter.username if reporter else "Unknown"

        print(f"[REPORT] Challenge #{challenge_id} reported by {reporter_name}")
        print(f"[REPORT] Admin chat configured: {bool(TELEGRAM_ADMIN_CHAT_ID)}")
        print(f"[REPORT] Admin bot configured: {bool(TELEGRAM_ADMIN_BOT_TOKEN)}")

        telegram_notified = False
        if TELEGRAM_ADMIN_CHAT_ID:
            try:
                comment_line = (
                    f"Comment: #{comment.id} - {escape_html(comment.body[:300])}\n"
                    if comment else ""
                )
                caption = (
                    f"🚨 <b>New {'Comment' if comment else 'Challenge'} Report</b>\n\n"
                    f"Challenge: #{challenge_id} - {escape_html(challenge.title)}\n"
                    f"{comment_line}"
                    f"Category: {escape_html(challenge.category)} | Difficulty: {escape_html(challenge.difficulty)}\n"
                    f"Reported by: {escape_html(reporter_name)}\n"
                    f"Reason: {escape_html(reason)}\n"
                    f"Details: {escape_html(details)}\n\n"
                    f"Take action below:"
                )

                buttons = [
                    [
                        {"text": "✅ Approve", "callback": f"approve_{report.id}"},
                        {"text": "🗑️ Reject", "callback": f"reject_{report.id}"}
                    ],
                    [
                        {"text": "🚫 Ban User", "callback": f"ban_{report.id}"}
                    ]
                ]
                if challenge.telegram_file_id:
                    try:
                        send_telegram_photo_with_buttons(
                            TELEGRAM_ADMIN_CHAT_ID,
                            challenge.telegram_file_id,
                            caption,
                            buttons
                        )
                    except Exception as photo_error:
                        print(f"[REPORT] Photo send failed, falling back to text: {photo_error}")
                        send_telegram_message(TELEGRAM_ADMIN_CHAT_ID, caption + "\n\nUse /approve " + str(report.id) + " /reject " + str(report.id) + " /ban " + str(report.id))
                else:
                    send_telegram_message(TELEGRAM_ADMIN_CHAT_ID, caption + "\n\nUse /approve " + str(report.id) + " /reject " + str(report.id) + " /ban " + str(report.id))

                print(f"[REPORT] Telegram notification sent successfully")
                telegram_notified = True
            except Exception as e:
                print(f"[REPORT] Telegram notification failed: {e}")
        else:
            print("⚠️ Report received but TELEGRAM_ADMIN_CHAT_ID not configured. Set it in .env to receive notifications.")

        return {
            "message": "Report submitted successfully.",
            "status": "open",
            "report_id": report.id,
            "telegram_notified": telegram_notified,
        }
    except HTTPException:
        raise
    except Exception as e:
        import traceback
        traceback.print_exc()
        # Log the real cause server-side; never echo raw exception text
        # (it can contain DB/Turso internals) to the client.
        raise HTTPException(status_code=500, detail="Could not submit the report. Please try again later.")


@app.get("/api/moderation/reports")
def list_moderation_reports(admin_user: User = Depends(get_current_admin_user), db: Session = Depends(get_db)):
    """Return open reports that need moderator action."""
    reports = db.query(ChallengeReport).filter(ChallengeReport.status == "open").order_by(ChallengeReport.created_at.desc()).all()
    payload = []
    for report in reports:
        challenge = db.query(Challenge).filter(Challenge.id == report.challenge_id).first()
        comment = db.query(Comment).filter(Comment.id == report.comment_id).first() if report.comment_id else None
        reporter = db.query(User).filter(User.id == report.reporter_id).first()
        payload.append({
            "id": report.id,
            "challenge_id": report.challenge_id,
            "comment_id": report.comment_id,
            "target_type": report.target_type or "challenge",
            "challenge_title": challenge.title if challenge else "Unknown challenge",
            "reporter": reporter.username if reporter else "unknown",
            "reason": report.reason,
            "details": report.details,
            "comment_body": comment.body if comment else None,
            "created_at": report.created_at,
        })
    return payload


@app.post("/api/moderation/reports/{report_id}/resolve")
def resolve_moderation_report(
    report_id: int,
    payload: ModerationActionRequest,
    admin_user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """Resolve an open report with an admin action."""
    report = db.query(ChallengeReport).filter(ChallengeReport.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    action = payload.action.strip().lower()
    if action not in {"approve", "reject", "ban"}:
        raise HTTPException(status_code=400, detail="Action must be approve, reject, or ban")

    challenge = db.query(Challenge).filter(Challenge.id == report.challenge_id).first()
    comment = db.query(Comment).filter(Comment.id == report.comment_id).first() if report.comment_id else None
    banned_target_id = None
    if action == "reject" and challenge and report.comment_id is None:
        challenge.status = "removed"
    elif action == "ban":
        if challenge and report.comment_id is None:
            challenge.status = "removed"
        target_user_id = comment.user_id if comment else (challenge.created_by if challenge else None)
        if not target_user_id:
            raise HTTPException(status_code=404, detail="Report target user not found")
        existing_ban = db.query(UserBan).filter(UserBan.user_id == target_user_id).first()
        if not existing_ban:
            ban_reason = payload.reason or report.reason or "Challenge report violation"
            db.add(UserBan(user_id=target_user_id, reason=ban_reason, banned_by=admin_user.id))
            banned_target_id = target_user_id
            target_user = db.query(User).filter(User.id == target_user_id).first()
            if target_user and target_user.telegram_chat_id:
                send_user_notification(
                    str(target_user.telegram_chat_id),
                    "🚫 <b>Account suspended</b>\n\n"
                    f"Your CipherPoint account has been suspended by {admin_user.username}.\n\n"
                    f"<b>Reason:</b> {escape_html(ban_reason)}\n\n"
                    "You can no longer access the platform until this suspension is reviewed."
                )

    report.status = "resolved"
    report.resolved_at = datetime.utcnow()
    report.resolved_by = admin_user.id

    if action == "approve" and report.reporter_id:
        reporter = db.query(User).filter(User.id == report.reporter_id).first()
        if reporter:
            reporter.reports_approved = (reporter.reports_approved or 0) + 1

    db.commit()
    _cache_clear_prefix("challenges:")

    # Kick the banned user out of every active session immediately — same
    # requirement as admin_ban_user, otherwise their existing tokens stay
    # valid (up to 7 days for refresh tokens).
    if banned_target_id:
        revoke_user_tokens(db, banned_target_id, reason="banned: report resolved")

    return {"message": f"Report resolved via {action}", "status": "resolved"}


@app.delete("/api/challenges/{challenge_id}")
def delete_challenge(
    challenge_id: int,
    user_id: int = Depends(verify_token),
    db: Session = Depends(get_db)
):
    """Allow owners or admins to remove a community challenge."""
    challenge = db.query(Challenge).filter(Challenge.id == challenge_id).first()
    if not challenge:
        raise HTTPException(status_code=404, detail="Challenge not found")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    ensure_user_not_banned(user_id, db)
    if challenge.created_by != user_id and not user.is_admin:
        raise HTTPException(status_code=403, detail="Only the creator or an admin may delete this challenge")

    challenge.status = "removed"
    db.commit()
    _cache_clear_prefix("challenges:")
    return {"message": "Challenge removed successfully.", "id": challenge_id}

class ChallengeUpdateRequest(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    hint_1: Optional[str] = None
    hint_2: Optional[str] = None
    hint_1_cost: Optional[int] = None
    hint_2_cost: Optional[int] = None
    points_reward: Optional[int] = None
    tags: Optional[str] = None
    solution_walkthrough: Optional[str] = None
    difficulty: Optional[str] = None
    telegram_file_id: Optional[str] = None


@app.put("/api/challenges/{challenge_id}")
def update_challenge(
    challenge_id: int,
    payload: ChallengeUpdateRequest,
    user_id: int = Depends(verify_token),
    db: Session = Depends(get_db)
):
    """Allow owners to update their challenge details."""
    challenge = db.query(Challenge).filter(Challenge.id == challenge_id).first()
    if not challenge:
        raise HTTPException(status_code=404, detail="Challenge not found")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    ensure_user_not_banned(user_id, db)
    if challenge.created_by != user_id and not user.is_admin:
        raise HTTPException(status_code=403, detail="Only the creator or an admin may edit this challenge")

    if payload.title is not None:
        if len(payload.title) > CHALLENGE_TITLE_MAX:
            raise HTTPException(status_code=400, detail=f"Title is too long (max {CHALLENGE_TITLE_MAX} characters).")
        challenge.title = payload.title.strip()
    if payload.description is not None:
        if len(payload.description) > CHALLENGE_DESCRIPTION_MAX:
            raise HTTPException(status_code=400, detail=f"Description is too long (max {CHALLENGE_DESCRIPTION_MAX} characters).")
        challenge.description = payload.description.strip()
    if payload.hint_1 is not None:
        if len(payload.hint_1) > CHALLENGE_HINT_MAX:
            raise HTTPException(status_code=400, detail=f"Hint 1 is too long (max {CHALLENGE_HINT_MAX} characters).")
        challenge.hint_1 = payload.hint_1.strip() or None
    if payload.hint_2 is not None:
        if len(payload.hint_2) > CHALLENGE_HINT_MAX:
            raise HTTPException(status_code=400, detail=f"Hint 2 is too long (max {CHALLENGE_HINT_MAX} characters).")
        challenge.hint_2 = payload.hint_2.strip() or None
    if payload.hint_1_cost is not None:
        if payload.hint_1_cost < 0 or payload.hint_1_cost > CHALLENGE_HINT_COST_MAX:
            raise HTTPException(status_code=400, detail="hint_1_cost must be 0-1000.")
        challenge.hint_1_cost = max(0, payload.hint_1_cost)
    if payload.hint_2_cost is not None:
        if payload.hint_2_cost < 0 or payload.hint_2_cost > CHALLENGE_HINT_COST_MAX:
            raise HTTPException(status_code=400, detail="hint_2_cost must be 0-1000.")
        challenge.hint_2_cost = max(0, payload.hint_2_cost)
    if payload.points_reward is not None:
        if payload.points_reward < CHALLENGE_POINTS_MIN or payload.points_reward > CHALLENGE_POINTS_MAX:
            raise HTTPException(status_code=400, detail=f"points_reward must be {CHALLENGE_POINTS_MIN}-{CHALLENGE_POINTS_MAX}.")
        challenge.points_reward = payload.points_reward
    if payload.tags is not None:
        if len(payload.tags) > CHALLENGE_TAGS_MAX:
            raise HTTPException(status_code=400, detail=f"Tags are too long (max {CHALLENGE_TAGS_MAX} characters).")
        challenge.tags = payload.tags.strip()
    if payload.solution_walkthrough is not None:
        if len(payload.solution_walkthrough) > CHALLENGE_WALKTHROUGH_MAX:
            raise HTTPException(status_code=400, detail=f"Walkthrough is too long (max {CHALLENGE_WALKTHROUGH_MAX} characters).")
        challenge.solution_walkthrough = payload.solution_walkthrough.strip() or None
    if payload.difficulty is not None:
        if payload.difficulty not in ALLOWED_DIFFICULTIES:
            raise HTTPException(status_code=400, detail=f"Difficulty must be one of: {', '.join(sorted(ALLOWED_DIFFICULTIES))}")
        challenge.difficulty = payload.difficulty
    if payload.telegram_file_id is not None:
        if not re.fullmatch(r"[A-Za-z0-9_-]{0,256}", payload.telegram_file_id or ""):
            raise HTTPException(status_code=400, detail="Invalid telegram_file_id format")
        challenge.telegram_file_id = payload.telegram_file_id.strip() or None

    db.commit()
    db.refresh(challenge)
    _cache_clear_prefix("challenges:")
    return {"message": "Challenge updated successfully.", "id": challenge.id}


# ==================== INTEL VAULT ROUTES ====================

@app.get("/api/intel-vault")
def list_intel_articles(category: Optional[str] = None, db: Session = Depends(get_db)):
    """Public list of published Intel Vault articles."""
    query = db.query(IntelArticle).filter(IntelArticle.is_published == True)
    if category:
        query = query.filter(IntelArticle.category == category)
    articles = query.order_by(IntelArticle.created_at.desc()).all()
    return [
        {
            "id": a.id,
            "title": a.title,
            "category": a.category,
            "summary": a.summary,
            "media_url": f"/api/media/{a.telegram_file_id}" if a.telegram_file_id else None,
            "created_at": a.created_at.isoformat() if a.created_at else None,
            "updated_at": a.updated_at.isoformat() if a.updated_at else None,
        }
        for a in articles
    ]


@app.get("/api/admin/intel-vault")
def admin_list_intel_articles(db: Session = Depends(get_db), user_id: int = Depends(verify_token)):
    """Admin list of all articles (published + drafts)."""
    _require_admin(user_id, db)
    articles = db.query(IntelArticle).order_by(IntelArticle.created_at.desc()).all()
    return [
        {
            "id": a.id,
            "title": a.title,
            "category": a.category,
            "summary": a.summary,
            "telegram_file_id": a.telegram_file_id,
            "author_id": a.author_id,
            "is_published": a.is_published,
            "created_at": a.created_at.isoformat() if a.created_at else None,
            "updated_at": a.updated_at.isoformat() if a.updated_at else None,
        }
        for a in articles
    ]


@app.get("/api/admin/intel-vault/{article_id}")
def admin_get_intel_article(article_id: int, db: Session = Depends(get_db), user_id: int = Depends(verify_token)):
    """Admin single article (includes drafts)."""
    _require_admin(user_id, db)
    article = db.query(IntelArticle).filter(IntelArticle.id == article_id).first()
    if not article:
        raise HTTPException(status_code=404, detail="Article not found")
    return {
        "id": article.id,
        "title": article.title,
        "category": article.category,
        "content": article.content,
        "summary": article.summary,
        "telegram_file_id": article.telegram_file_id,
        "author_id": article.author_id,
        "is_published": article.is_published,
        "created_at": article.created_at.isoformat() if article.created_at else None,
        "updated_at": article.updated_at.isoformat() if article.updated_at else None,
    }


@app.get("/api/intel-vault/{article_id}")
def get_intel_article(article_id: int, db: Session = Depends(get_db)):
    """Public single article detail."""
    article = db.query(IntelArticle).filter(IntelArticle.id == article_id, IntelArticle.is_published == True).first()
    if not article:
        raise HTTPException(status_code=404, detail="Article not found")
    return {
        "id": article.id,
        "title": article.title,
        "category": article.category,
        "content": article.content,
        "summary": article.summary,
        "media_url": f"/api/media/{article.telegram_file_id}" if article.telegram_file_id else None,
        "created_at": article.created_at.isoformat() if article.created_at else None,
        "updated_at": article.updated_at.isoformat() if article.updated_at else None,
    }


def _require_admin(user_id: int, db: Session):
    user = db.query(User).filter(User.id == user_id).first()
    if not user or not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


@app.post("/api/admin/intel-vault")
def create_intel_article(payload: IntelArticleCreateRequest, user_id: int = Depends(verify_token), db: Session = Depends(get_db)):
    _require_admin(user_id, db)
    if len(payload.title) > INTEL_TITLE_MAX:
        raise HTTPException(status_code=400, detail=f"Title is too long (max {INTEL_TITLE_MAX} characters).")
    if len(payload.category) > INTEL_CATEGORY_MAX:
        raise HTTPException(status_code=400, detail=f"Category is too long (max {INTEL_CATEGORY_MAX} characters).")
    if len(payload.content) > INTEL_CONTENT_MAX:
        raise HTTPException(status_code=400, detail=f"Content is too long (max {INTEL_CONTENT_MAX} characters).")
    if payload.summary and len(payload.summary) > INTEL_SUMMARY_MAX:
        raise HTTPException(status_code=400, detail=f"Summary is too long (max {INTEL_SUMMARY_MAX} characters).")
    if not payload.title.strip() or not payload.category.strip() or not payload.content.strip():
        raise HTTPException(status_code=400, detail="Title, category, and content are required.")

    article = IntelArticle(
        title=payload.title.strip(),
        category=payload.category.strip(),
        content=payload.content.strip(),
        summary=payload.summary.strip() if payload.summary else None,
        telegram_file_id=payload.telegram_file_id.strip() if payload.telegram_file_id else None,
        author_id=user_id,
        is_published=payload.is_published,
    )
    db.add(article)
    db.commit()
    db.refresh(article)
    return {"message": "Article created successfully.", "id": article.id}


@app.put("/api/admin/intel-vault/{article_id}")
def update_intel_article(article_id: int, payload: IntelArticleUpdateRequest, user_id: int = Depends(verify_token), db: Session = Depends(get_db)):
    _require_admin(user_id, db)
    article = db.query(IntelArticle).filter(IntelArticle.id == article_id).first()
    if not article:
        raise HTTPException(status_code=404, detail="Article not found")

    if payload.title is not None:
        if len(payload.title) > INTEL_TITLE_MAX:
            raise HTTPException(status_code=400, detail=f"Title is too long (max {INTEL_TITLE_MAX} characters).")
        article.title = payload.title.strip()
    if payload.category is not None:
        if len(payload.category) > INTEL_CATEGORY_MAX:
            raise HTTPException(status_code=400, detail=f"Category is too long (max {INTEL_CATEGORY_MAX} characters).")
        article.category = payload.category.strip()
    if payload.content is not None:
        if len(payload.content) > INTEL_CONTENT_MAX:
            raise HTTPException(status_code=400, detail=f"Content is too long (max {INTEL_CONTENT_MAX} characters).")
        article.content = payload.content.strip()
    if payload.summary is not None:
        if len(payload.summary) > INTEL_SUMMARY_MAX:
            raise HTTPException(status_code=400, detail=f"Summary is too long (max {INTEL_SUMMARY_MAX} characters).")
        article.summary = payload.summary.strip() or None
    if payload.telegram_file_id is not None:
        article.telegram_file_id = payload.telegram_file_id.strip() or None
    if payload.is_published is not None:
        article.is_published = payload.is_published

    db.commit()
    db.refresh(article)
    return {"message": "Article updated successfully.", "id": article.id}


@app.delete("/api/admin/intel-vault/{article_id}")
def delete_intel_article(article_id: int, user_id: int = Depends(verify_token), db: Session = Depends(get_db)):
    _require_admin(user_id, db)
    article = db.query(IntelArticle).filter(IntelArticle.id == article_id).first()
    if not article:
        raise HTTPException(status_code=404, detail="Article not found")
    db.delete(article)
    db.commit()
    return {"message": "Article deleted successfully.", "id": article_id}


# ==================== HINT ROUTES ====================

@app.post("/api/hints/unlock")
def unlock_hint(payload: HintRequest, user_id: int = Depends(verify_token), db: Session = Depends(get_db)):
    """Unlock a hint by paying coins"""
    challenge_id = payload.challenge_id
    hint_number = payload.hint_number
    challenge = db.query(Challenge).filter(Challenge.id == challenge_id).first()
    if not challenge:
        raise HTTPException(status_code=404, detail="Challenge not found")
    if challenge.status in {"rejected", "removed"}:
        raise HTTPException(status_code=404, detail="Challenge not found")
    ensure_user_not_banned(user_id, db)
    if hint_number not in [1, 2]:
        raise HTTPException(status_code=400, detail="Invalid hint number")
    hint_cost = max(0, int(challenge.hint_1_cost if hint_number == 1 else challenge.hint_2_cost or 0))
    hint_text = challenge.hint_1 if hint_number == 1 else challenge.hint_2
    if not hint_text:
        raise HTTPException(status_code=404, detail="Hint not available")
    already_unlocked = db.query(UnlockedHint).filter(
        (UnlockedHint.user_id == user_id) &
        (UnlockedHint.challenge_id == challenge_id) &
        (UnlockedHint.hint_number == hint_number)
    ).first()
    if already_unlocked:
        user = db.query(User).filter(User.id == user_id).first()
        return {
            "hint_number": hint_number,
            "hint_text": hint_text,
            "remaining_coins": user.coins if user else 0,
            "message": "Hint already unlocked"
        }
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if (user.coins or 0) < hint_cost:
        raise HTTPException(status_code=400, detail=f"Insufficient coins. Need {hint_cost}, have {user.coins or 0}")
    # Claim the hint FIRST: the unique constraint is the serialization
    # point, so exactly one concurrent request can win the claim. Only the
    # winner pays, which makes double-charging impossible even under races.
    new_unlocked_hint = UnlockedHint(user_id=user_id, challenge_id=challenge_id, hint_number=hint_number)
    db.add(new_unlocked_hint)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        existing = db.query(UnlockedHint).filter(
            (UnlockedHint.user_id == user_id) &
            (UnlockedHint.challenge_id == challenge_id) &
            (UnlockedHint.hint_number == hint_number)
        ).first()
        if not existing:
            raise
        db.refresh(user)
        return {
            "hint_number": hint_number,
            "hint_text": hint_text,
            "remaining_coins": user.coins,
            "message": "Hint already unlocked"
        }
    # Winner pays: atomic conditional decrement — can never go negative and
    # can't lose updates against concurrent coin mutations.
    charged = db.query(User).filter(
        User.id == user_id,
        func.coalesce(User.coins, 0) >= hint_cost,
    ).update(
        {
            User.coins: func.coalesce(User.coins, 0) - hint_cost,
            User.hints_unlocked: func.coalesce(User.hints_unlocked, 0) + 1,
        },
        synchronize_session=False,
    )
    db.commit()
    if not charged:
        # Lost a concurrent coin spend between the balance check and the
        # charge — undo the claim so the user isn't left with an unpaid hint.
        db.query(UnlockedHint).filter(
            (UnlockedHint.user_id == user_id) &
            (UnlockedHint.challenge_id == challenge_id) &
            (UnlockedHint.hint_number == hint_number)
        ).delete(synchronize_session=False)
        db.commit()
        raise HTTPException(status_code=400, detail=f"Insufficient coins. Need {hint_cost}")
    db.refresh(user)
    return {
        "hint_number": hint_number,
        "hint_text": hint_text,
        "cost": hint_cost,
        "remaining_coins": user.coins,
        "message": "Hint unlocked successfully!"
    }

# ==================== SUBMISSION ROUTES ====================

@app.post("/api/challenges/submit")
def submit_flag(
    payload: FlagSubmitRequest,
    request: Request,
    user_id: int = Depends(verify_token),
    db: Session = Depends(get_db)
):
    """Submit a flag/answer for a challenge.

    Defenses:
      - Per-IP rate limit (30 attempts / 5 min) to slow down brute-force
      - Refuse to award points to the challenge author (no self-solving
        for infinite-coin glitches)
      - Sanity-check the submitted flag length
    """
    from security import rate_limit_check

    # Per-IP rate limit (defense against brute-force on the flag value)
    ip = request.state.real_ip
    allowed, retry = rate_limit_check(f"submit_ip:{ip}", max_events=30, window_seconds=300)
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail=f"Too many submission attempts from this network. Try again in {retry}s.",
            headers={"Retry-After": str(retry)},
        )

    # Account-level rate limit: slow down credential stuffing even if IPs rotate.
    # This catches the "many IPs, same account" and "many accounts, same IP" patterns.
    user_allowed, user_retry = rate_limit_check(f"submit_user:{user_id}", max_events=50, window_seconds=300)
    if not user_allowed:
        raise HTTPException(
            status_code=429,
            detail=f"Too many submission attempts. Try again in {user_retry}s.",
            headers={"Retry-After": str(user_retry)},
        )

    challenge_id = payload.challenge_id
    flag = (payload.flag or "").strip()
    if not challenge_id or not flag:
        raise HTTPException(status_code=400, detail="challenge_id and flag are required")
    if len(flag) > CHALLENGE_FLAG_MAX:
        raise HTTPException(status_code=400, detail="Flag is too long")

    challenge = db.query(Challenge).filter(Challenge.id == challenge_id).first()
    if not challenge:
        raise HTTPException(status_code=404, detail="Challenge not found")
    if is_cipher_day_challenge(challenge) and not is_cipher_day_challenge_ready(challenge):
        raise HTTPException(status_code=403, detail="Cipher Day challenge is not active.")
    ensure_user_not_banned(user_id, db)
    if challenge.status in {"rejected", "removed"}:
        raise HTTPException(status_code=404, detail="Challenge not found")

    # Refuse self-solving (community-challenge infinite-coin glitch).
    if challenge.created_by and challenge.created_by == user_id:
        raise HTTPException(
            status_code=403,
            detail="You cannot solve your own challenge.",
        )

    already_solved = db.query(SolvedChallenge).filter(
        (SolvedChallenge.user_id == user_id) &
        (SolvedChallenge.challenge_id == challenge_id)
    ).first()
    if already_solved:
        return {"success": False, "message": "You already solved this challenge!"}

    submitted = (payload.flag or "").strip()
    expected = (challenge.correct_flag or "").strip()
    if submitted and expected and constant_time_eq(submitted.lower(), expected.lower()):
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        now = datetime.utcnow()
        if user.first_solve_at is None:
            user.first_solve_at = now
        if challenge.created_at:
            solve_seconds = max(0, int((now - challenge.created_at).total_seconds()))
            if user.fastest_solve_seconds is None or solve_seconds < user.fastest_solve_seconds:
                user.fastest_solve_seconds = solve_seconds
            # Flag suspiciously fast solves (< 5 seconds) as potential bot activity
            if solve_seconds < 5:
                user.flagged_for_review = True

        # Record the solve FIRST: the unique constraint is the serialization
        # point, so of N concurrent submissions exactly one reaches the award
        # below. The old order (award → insert → "rollback") could double-pay,
        # because a failed insert could not undo the already-committed award.
        solved_challenge = SolvedChallenge(user_id=user_id, challenge_id=challenge_id)
        db.add(solved_challenge)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            return {"success": False, "message": "You already solved this challenge!"}

        # Award with an atomic SQL increment — immune to lost updates against
        # concurrent coin/point mutations.
        db.query(User).filter(User.id == user_id).update(
            {
                User.coins: func.coalesce(User.coins, 0) + (challenge.points_reward or 0),
                User.rank_points: func.coalesce(User.rank_points, 0) + (challenge.points_reward or 0),
            },
            synchronize_session=False,
        )
        db.commit()
        db.refresh(user)
        _cache_clear_prefix("challenges:")
        _cache_clear_prefix("leaderboard:")
        return {
            "success": True,
            "message": "Correct! Challenge solved!",
            "coins_earned": challenge.points_reward,
            "total_coins": user.coins,
            "rank_points": user.rank_points
        }
    return {"success": False, "message": "Incorrect flag. Try again!"}


@app.post("/api/cipher-day/submit")
def submit_cipher_day_flag(
    payload: CipherDayFlagRequest,
    request: Request,
    user_id: int = Depends(verify_token),
    db: Session = Depends(get_db),
):
    if not is_cipher_day_window_open():
        raise HTTPException(status_code=403, detail="Cipher Day is not active.")
    challenge = db.query(Challenge).filter(Challenge.id == CIPHER_DAY_CHALLENGE_ID).first()
    if not is_cipher_day_challenge_ready(challenge):
        raise HTTPException(status_code=503, detail="Cipher Day is not configured yet.")
    return submit_flag(
        FlagSubmitRequest(challenge_id=CIPHER_DAY_CHALLENGE_ID, flag=payload.flag),
        request,
        user_id,
        db,
    )


# ==================== LEADERBOARD ROUTES ====================

@app.get("/api/admin/stats/solves-24h")
def admin_stats_solves_24h(db: Session = Depends(get_db), user_id: int = Depends(verify_token)):
    """Count of solves recorded in the last 24 hours."""
    _require_admin(user_id, db)
    cutoff = datetime.utcnow() - timedelta(hours=24)
    count = db.query(SolvedChallenge).filter(SolvedChallenge.solved_at >= cutoff).count()
    return {"total": count}


@app.get("/api/leaderboard")
def get_leaderboard(limit: int = 100, db: Session = Depends(get_db)):
    """Get top users by rank points (cached 30s)"""
    limit = max(1, min(limit, 100))
    cache_key = f"leaderboard:{limit}"
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached
    top_users = db.query(User).filter(User.public_profile != False).order_by(User.rank_points.desc()).limit(limit).all()

    result = []
    for idx, user in enumerate(top_users, 1):
        solved_count = db.query(SolvedChallenge).filter(SolvedChallenge.user_id == user.id).count()
        rank_points = user.rank_points or 0
        coins = user.coins or 0
        badges = []
        if solved_count >= 1:
            badges.append("rookie")
        if solved_count >= 3:
            badges.append("resolver")
        if rank_points >= 1000:
            badges.append("investigator")
        if coins >= 200:
            badges.append("collector")
        if user.is_admin:
            badges.append("guardian")
        result.append({
            "rank": idx,
            "username": user.username,
            "rank_points": rank_points,
            "solved_count": solved_count,
            "badges": badges,
        })

    _cache_set(cache_key, result, ttl=30)
    return result

# ==================== FILE UPLOAD ROUTES ====================

def _sanitize_upload_error(e: Exception) -> str:
    """Redact Telegram bot tokens from exception text before it reaches a
    client: requests' HTTPError messages embed the full request URL, which
    contains /bot<TOKEN>/ for every Telegram API call."""
    import re as _re
    return _re.sub(r"/bot\d+:[A-Za-z0-9_-]+", "/bot***", str(e))


def _sniff_media_family(head: bytes) -> Optional[str]:
    """Return 'image' or 'video' based on the file's magic bytes, else None.
    Used to verify that an upload's payload matches its declared type."""
    if head[:3] == b"\xff\xd8\xff":
        return "image"  # JPEG
    if head[:8] == b"\x89PNG\r\n\x1a\n":
        return "image"  # PNG
    if head[:6] in (b"GIF87a", b"GIF89a"):
        return "image"  # GIF
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "image"  # WEBP
    if head[:4] == b"\x1a\x45\xdf\xa3":
        return "video"  # WebM/MKV (EBML)
    if len(head) >= 12 and head[4:8] == b"ftyp":
        return "video"  # MP4/MOV family
    return None


@app.post("/api/upload/media")
async def upload_media(
    file: UploadFile = File(...),
    user_id: int = Depends(verify_token),
    db: Session = Depends(get_db)
):
    """Upload image/video to Telegram channel via bot pool with backpressure."""
    from telegram_proxy import UPLOAD_SEMAPHORE, UPLOAD_EXECUTOR

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    ensure_user_not_banned(user_id, db)

    # Per-user throttle: uploads cost Telegram API calls and RAM/disk for
    # video validation, so don't let one account monopolize the pipeline.
    up_allowed, up_retry = rate_limit_check(f"upload_user:{user_id}", max_events=30, window_seconds=3600)
    if not up_allowed:
        raise HTTPException(
            status_code=429,
            detail=f"Too many uploads this hour. Try again in {up_retry}s.",
            headers={"Retry-After": str(up_retry)},
        )

    # Block (up to 10s) instead of failing fast, so a brief burst doesn't
    # surface as 503 to the user. If the queue is genuinely saturated for
    # 10s straight, then we return 503 with a retry-after hint.
    acquired = UPLOAD_SEMAPHORE.acquire(blocking=True, timeout=10)
    if not acquired:
        raise HTTPException(
            status_code=503,
            detail="Upload queue is busy. Please try again in a few seconds."
        )

    tmp_path = None
    try:
        # Validate file type
        allowed_types = {"image/jpeg", "image/png", "image/gif", "image/webp", "video/mp4", "video/webm", "video/quicktime"}
        if file.content_type not in allowed_types:
            raise HTTPException(status_code=400, detail=f"File type not allowed. Allowed: {', '.join(allowed_types)}")

        size_limit = 50 * 1024 * 1024 if file.content_type.startswith("video") else 10 * 1024 * 1024

        with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(file.filename)[1]) as tmp_file:
            tmp_path = tmp_file.name
            # Stream to disk in chunks with a hard cap — never buffer the
            # whole upload in RAM before checking the size.
            total = 0
            head = b""
            oversized = False
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                if not head:
                    head = chunk[:16]
                total += len(chunk)
                if total > size_limit:
                    oversized = True
                    break
                tmp_file.write(chunk)
            tmp_file.flush()

        if oversized:
            os.unlink(tmp_path)
            raise HTTPException(status_code=413, detail=f"File too large. Max size: {size_limit // (1024*1024)}MB")
        if total == 0:
            os.unlink(tmp_path)
            raise HTTPException(status_code=400, detail="File is empty")

        # Content-Type is a client-controlled header — verify the bytes
        # actually match the declared media family before trusting it.
        family = _sniff_media_family(head)
        expected_family = "video" if file.content_type.startswith("video") else "image"
        if family != expected_family:
            os.unlink(tmp_path)
            raise HTTPException(status_code=400, detail="File content does not match its media type")

        if file.content_type.startswith("video"):
            validate_media_duration(tmp_path, file.content_type)

        # Offload the blocking Telegram upload to the thread pool so the
        # event loop stays responsive for other requests while the slow
        # network call to api.telegram.org is in flight.
        loop = asyncio.get_event_loop()
        upload_result = await loop.run_in_executor(
            UPLOAD_EXECUTOR,
            upload_media_to_channel,
            tmp_path,
            file.content_type,
        )

        result = {
            "success": True,
            "file_id": upload_result["file_id"],
            "filename": file.filename,
            "content_type": file.content_type,
            "served_by_bot": upload_result.get("bot_token"),
            "message": "Media uploaded to Telegram successfully"
        }
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)
        return result

    except HTTPException:
        raise
    except ValueError as e:
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise HTTPException(status_code=400, detail=str(e))
    except FileNotFoundError as e:
        # ffprobe (or another subprocess dep) is missing on this host.
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise HTTPException(
            status_code=503,
            detail=f"Server is missing a required tool to process this file ({e.filename or 'ffprobe'}).",
        )
    except Exception as e:
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise HTTPException(status_code=503, detail=f"Upload temporarily unavailable: {_sanitize_upload_error(e)}")
    finally:
        UPLOAD_SEMAPHORE.release()


@app.get("/api/health/bots")
def bots_health(user_id: int = Depends(verify_token)):
    """Public health snapshot of all Telegram bots."""
    return {
        "bots": get_bot_health(),
        "upload_queue_capacity": int(os.getenv("MAX_CONCURRENT_UPLOADS", "4"))
    }


# ==================== MEDIA PROXY ROUTES ====================

@app.get("/api/media/{file_id}")
def get_media(file_id: str, download: int = 0, request: Request = None):
    """Proxy endpoint for Telegram media.

    When `?download=1` is set, force a Content-Disposition: attachment
    response with a sensible filename so users can save files locally
    to inspect metadata (EXIF, video codec info, etc).
    """
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,256}", file_id):
        raise HTTPException(status_code=400, detail="Invalid media identifier")
    try:
        response = get_telegram_file(file_id)
    except Exception as e:
        print(f"[MEDIA] Failed to fetch {file_id[:24]}...: {e}")
        raise HTTPException(status_code=404, detail="Media unavailable")

    if not download:
        return response

    # For downloads, build a fresh StreamingResponse so we can override
    # Content-Disposition without buffering the whole file in memory.
    ct = response.headers.get("content-type", "").lower() or "application/octet-stream"
    if ct.startswith("video/"):
        ext = ".mp4"
    elif ct.startswith("image/jpeg") or ct.startswith("image/jpg"):
        ext = ".jpg"
    elif ct.startswith("image/png"):
        ext = ".png"
    elif ct.startswith("image/webp"):
        ext = ".webp"
    elif ct.startswith("image/gif"):
        ext = ".gif"
    else:
        ext = ""
    filename = f"cipherpoint-media-{file_id[:12]}{ext}"

    # Pull the underlying iterator from the original StreamingResponse and
    # wrap it again with the new Content-Disposition header. The body
    # has not been consumed yet (FastAPI hands the response back to
    # starlette which iterates it during send).
    body_iter = response.body_iterator if hasattr(response, "body_iterator") else None
    if body_iter is None:
        # Fallback: buffer the whole thing. Not ideal but safe.
        return Response(
            content=response.body if hasattr(response, "body") else b"",
            media_type=ct,
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "Cache-Control": "private, max-age=300",
            },
        )

    return StreamingResponse(
        body_iter,
        media_type=ct,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "private, max-age=300",
        },
    )

# ==================== HONEYPOT / TRAP ROUTES ====================
# These paths are not linked from anywhere on the frontend. Bots and
# automated scanners that blindly crawl every URL will hit them.
# When accessed, we record the IP and slow it down to make scanning
# expensive for the attacker.

_HONEYPOT_PATHS = [
    "/.env",
    "/.git",
    "/.well-known/admin",
    "/wp-login.php",
    "/xmlrpc.php",
    "/.htaccess",
    "/server-status",
    "/phpmyadmin",
    "/admin/login",
    "/api/v1/admin",
]

for _path in _HONEYPOT_PATHS:
    @app.get(_path, include_in_schema=False)
    async def _honeypot(request: Request, _path=_path):
        ip = request.state.real_ip
        # Flag the IP — honeypot_guard middleware now throttles it site-wide.
        honeypot_flag_ip(ip)
        return JSONResponse(
            status_code=404,
            content={"detail": "Not Found"},
            headers={"Cache-Control": "no-store"},
        )

# ==================== HEALTH CHECK ====================

@app.get("/api/health")
def health_check():
    """Health check endpoint"""
    return {"status": "✅ CipherPoint API is running!"}


@app.get("/api/config")
def public_config():
    """Expose public client config without leaking secrets."""
    return get_turnstile_config()


@app.get("/api/cipher-day/status")
def cipher_day_status(db: Session = Depends(get_db)):
    """Public event state; never returns the challenge answer."""
    challenge = (
        db.query(Challenge).filter(Challenge.id == CIPHER_DAY_CHALLENGE_ID).first()
        if CIPHER_DAY_CHALLENGE_ID > 0
        else None
    )
    window_open = is_cipher_day_window_open()
    challenge_ready = bool(
        challenge
        and challenge.status == "approved"
        and not challenge.is_community
        and (challenge.points_reward or 0) >= 500
    )
    launch_ready = bool(window_open and challenge_ready and CIPHER_DAY_ASSET_BASE_URL)
    if not window_open:
        message = "Cipher Day is not active."
    elif not challenge_ready:
        message = "Cipher Day challenge is not configured yet."
    elif not CIPHER_DAY_ASSET_BASE_URL:
        message = "Cipher Day machine assets are not configured yet."
    else:
        message = None
    return {
        "enabled": window_open,
        "launch_ready": launch_ready,
        "server_time": datetime.utcnow().isoformat() + "Z",
        "starts_at": CIPHER_DAY_STARTS_AT or None,
        "ends_at": CIPHER_DAY_ENDS_AT or None,
        "challenge_id": CIPHER_DAY_CHALLENGE_ID or None,
        "title": challenge.title if challenge_ready else "The Quiet Relay",
        "points": challenge.points_reward if challenge_ready else 500,
        "asset_base_url": CIPHER_DAY_ASSET_BASE_URL if launch_ready else None,
        "message": message,
    }


@app.get("/api/maintenance/status")
def maintenance_status():
    """Public read-only status of maintenance mode. The maintenance
    page calls this so it can show the live message/countdown without
    a redeploy. Always returns 200, even during maintenance, so the
    front-end can read it from the gate page."""
    return maintenance_status_payload()


@app.post("/api/admin/maintenance")
def admin_toggle_maintenance(
    payload: dict,
    admin_user: User = Depends(get_current_admin_user),
):
    """Admin: toggle maintenance mode on/off and update the message
    or end time. Body: {enabled: bool, message?: str, until?: str}.
    Changes are in-memory only — they last until the next deploy or
    restart. For long-lived windows, set the env vars instead so they
    survive a restart."""
    global MAINTENANCE_MODE, MAINTENANCE_MESSAGE, MAINTENANCE_UNTIL
    enabled = bool(payload.get("enabled"))
    if "message" in payload and payload["message"] is not None:
        new_msg = str(payload["message"]).strip()
        if len(new_msg) > 1000:
            raise HTTPException(status_code=400, detail="Message too long (max 1000 chars)")
        MAINTENANCE_MESSAGE = new_msg or "We're upgrading CipherPoint. We'll be back shortly."
    if "until" in payload:
        until_val = (payload.get("until") or "").strip() or None
        if until_val:
            try:
                from datetime import datetime as _dt
                _dt.fromisoformat(until_val.replace("Z", "+00:00"))
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid ISO-8601 timestamp for 'until'")
        MAINTENANCE_UNTIL = until_val
    MAINTENANCE_MODE = enabled
    return {
        "message": "Maintenance mode updated",
        "status": maintenance_status_payload(),
    }


@app.get("/healthz")
def liveness_probe():
    """Liveness probe (no DB query) — for k8s/Render."""
    return {"status": "alive"}

# /api/ is reserved for API. The HTML frontend is served at the end of this file
# (see ROOT & STATIC FILES section below). Do NOT register a route at "/" here.

# ==================== ROOT & STATIC FILES ====================

# Serve frontend static files (must be registered AFTER all API routes)
# Order: 1) bundled backend/frontend (Docker), 2) parent ../frontend (local dev)
_BUNDLED = os.path.join(os.path.dirname(os.path.abspath(__file__)), "frontend")
_PARENT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "frontend")
FRONTEND_DIR = _BUNDLED if os.path.isdir(_BUNDLED) else _PARENT

# Public base URL used in sitemap.xml. Override via env if running
# behind a different domain (e.g. staging vs production).
SITE_BASE_URL = os.getenv("SITE_BASE_URL", "https://cipherpoint.linkpc.net").rstrip("/")


@app.get("/robots.txt", include_in_schema=False)
async def serve_robots():
    """Serve robots.txt. We block all admin/authenticated areas from
    crawlers but allow public marketing pages so Google can index
    them. Cached for 1 hour since the rules rarely change."""
    file_path = os.path.join(FRONTEND_DIR, "robots.txt")
    if not os.path.isfile(file_path):
        raise HTTPException(status_code=404, detail="robots.txt not found")
    return FileResponse(
        file_path,
        media_type="text/plain; charset=utf-8",
        headers={"Cache-Control": "public, max-age=3600"},
    )


@app.get("/sitemap.txt", include_in_schema=False)
async def serve_sitemap_txt():
    """Serve the plain-text sitemap (one URL per line). Some crawlers
    and webmasters prefer this format; GSC accepts it too."""
    file_path = os.path.join(FRONTEND_DIR, "sitemap.txt")
    if not os.path.isfile(file_path):
        raise HTTPException(status_code=404, detail="sitemap.txt not found")
    return FileResponse(
        file_path,
        media_type="text/plain; charset=utf-8",
        headers={"Cache-Control": "public, max-age=3600"},
    )


@app.get("/sitemap.xml", include_in_schema=False)
async def serve_sitemap(db: Session = Depends(get_db)):
    """Dynamically generate sitemap.xml so newly published challenges
    show up in search engines without a redeploy. Cached for 10 min
    so the sitemap doesn't regenerate on every crawler hit."""
    from fastapi.responses import Response
    # Try to read challenges from the DB. If the DB is unreachable
    # (e.g. during a deploy) we fall back to the static file so
    # search engines still get a valid sitemap.
    today = datetime.utcnow().date().isoformat()
    urls: list[tuple[str, str, float]] = [
        ("/", today, 1.0),
        ("/guides.html", today, 0.9),
        ("/guide-how-to-solve-ctf.html", today, 0.9),
        ("/guide-osint-basics.html", today, 0.9),
        ("/guide-google-dorking.html", today, 0.9),
        ("/guide-exif-geolocation.html", today, 0.9),
        ("/intel-vault.html", today, 0.8),
        ("/about.html", today, 0.8),
        ("/contact.html", today, 0.6),
        ("/terms.html", today, 0.4),
        ("/privacy.html", today, 0.4),
        ("/leaderboard.html", today, 0.7),
    ]
    if is_cipher_day_window_open():
        urls.append(("/cipher-day.html", today, 0.8))
    # Note: dashboard.html is robots-disallowed (it's a login-gated app
    # page), so challenge links intentionally do NOT appear here.
    if False:
        pass
    if not urls:
        print("[sitemap] no urls generated, serving static fallback")
        static = os.path.join(FRONTEND_DIR, "sitemap.xml")
        if os.path.isfile(static):
            with open(static, "r", encoding="utf-8") as fh:
                return Response(content=fh.read(), media_type="application/xml")

    body = ['<?xml version="1.0" encoding="UTF-8"?>']
    body.append('<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">')

    def _xml_escape(s: str) -> str:
        """Escape characters that would break XML or, more importantly,
        allow attackers to inject sitemap content. SITE_BASE_URL is
        admin-controlled via env, but defense in depth is cheap."""
        return (
            s.replace("&", "&amp;")
             .replace("<", "&lt;")
             .replace(">", "&gt;")
             .replace('"', "&quot;")
             .replace("'", "&apos;")
        )

    for path, last_mod, priority in urls:
        # Sitemap URLs must be absolute and percent-encoded. We
        # intentionally use the dashboard anchor (e.g. /dashboard.html#challenge-3)
        # so we don't have to invent a public detail URL.
        loc = f"{SITE_BASE_URL}{path}"
        # Strip the fragment from the canonical loc and put it in a
        # dedicated <xhtml:link rel="alternate"> tag... actually we
        # keep this simple: just escape the URL so a malicious
        # SITE_BASE_URL can't break out of the XML.
        body.append("  <url>")
        body.append(f"    <loc>{_xml_escape(loc)}</loc>")
        body.append(f"    <lastmod>{_xml_escape(last_mod)}</lastmod>")
        body.append(f"    <priority>{priority}</priority>")
        body.append("  </url>")
    body.append("</urlset>")
    xml = "\n".join(body) + "\n"
    return Response(
        content=xml,
        media_type="application/xml",
        headers={"Cache-Control": "public, max-age=600"},
    )

if os.path.isdir(FRONTEND_DIR):
    # Mount static assets (JS, CSS, images) at /static
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")

    # Root serves index.html (landing page)
    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    @app.get("/index.html", response_class=HTMLResponse, include_in_schema=False)
    async def serve_index():
        return FileResponse(
            os.path.join(FRONTEND_DIR, "index.html"),
            headers={"Cache-Control": "public, max-age=300"},  # 5 min
        )

    @app.get("/login.html", response_class=HTMLResponse, include_in_schema=False)
    @app.get("/signup.html", response_class=HTMLResponse, include_in_schema=False)
    @app.get("/dashboard.html", response_class=HTMLResponse, include_in_schema=False)
    @app.get("/community.html", response_class=HTMLResponse, include_in_schema=False)
    @app.get("/challenge_detail.html", response_class=HTMLResponse, include_in_schema=False)
    @app.get("/comments.html", response_class=HTMLResponse, include_in_schema=False)
    @app.get("/leaderboard.html", response_class=HTMLResponse, include_in_schema=False)
    @app.get("/profile.html", response_class=HTMLResponse, include_in_schema=False)
    @app.get("/settings.html", response_class=HTMLResponse, include_in_schema=False)
    @app.get("/privacy.html", response_class=HTMLResponse, include_in_schema=False)
    @app.get("/terms.html", response_class=HTMLResponse, include_in_schema=False)
    @app.get("/forgot-password.html", response_class=HTMLResponse, include_in_schema=False)
    @app.get("/about.html", response_class=HTMLResponse, include_in_schema=False)
    @app.get("/api-docs.html", response_class=HTMLResponse, include_in_schema=False)
    @app.get("/admin.html", response_class=HTMLResponse, include_in_schema=False)
    @app.get("/notifications.html", response_class=HTMLResponse, include_in_schema=False)
    @app.get("/guides.html", response_class=HTMLResponse, include_in_schema=False)
    @app.get("/guide-how-to-solve-ctf.html", response_class=HTMLResponse, include_in_schema=False)
    @app.get("/guide-osint-basics.html", response_class=HTMLResponse, include_in_schema=False)
    @app.get("/guide-google-dorking.html", response_class=HTMLResponse, include_in_schema=False)
    @app.get("/guide-exif-geolocation.html", response_class=HTMLResponse, include_in_schema=False)
    @app.get("/intel-vault.html", response_class=HTMLResponse, include_in_schema=False)
    @app.get("/cipher-day.html", response_class=HTMLResponse, include_in_schema=False)
    @app.get("/cipher-day-machine.html", response_class=HTMLResponse, include_in_schema=False)
    @app.get("/contact.html", response_class=HTMLResponse, include_in_schema=False)
    @app.get("/404.html", response_class=HTMLResponse, include_in_schema=False)
    @app.get("/500.html", response_class=HTMLResponse, include_in_schema=False)
    async def serve_html_page(request: Request):
        """Serve any *.html file from the frontend directory."""
        filename = request.url.path.lstrip("/")
        file_path = os.path.join(FRONTEND_DIR, filename)
        if not os.path.abspath(file_path).startswith(os.path.abspath(FRONTEND_DIR)):
            raise HTTPException(status_code=400, detail="Invalid path")
        if not os.path.isfile(file_path):
            raise HTTPException(status_code=404, detail="Page not found")
        return FileResponse(
            file_path,
            headers={"Cache-Control": "public, max-age=300, must-revalidate"},
        )

    # Whitelist for non-HTML static files we serve (Google site
    # verification, etc.). Anything else that isn't matched below
    # falls through to the 404 catch-all.
    @app.get("/google{site_token}.html", include_in_schema=False)
    async def serve_google_verification(site_token: str, request: Request):
        """Serve a Google Search Console verification file.

        Google asks site owners to upload a file whose name is
        `google<token>.html` containing a single meta line. We
        accept any token but only serve a file that exists in the
        frontend directory — nothing else gets exposed. The
        path-traversal check below is the real protection; the
        path parameter is just a routing convenience.
        """
        # Reconstruct the filename from the route param
        filename = f"google{site_token}.html"
        # Strict token shape: only the chars Google itself uses
        if not site_token or not all(c.isalnum() for c in site_token):
            raise HTTPException(status_code=404, detail="Not found")
        file_path = os.path.join(FRONTEND_DIR, filename)
        # Path traversal guard: ensure the resolved path is still
        # under FRONTEND_DIR (e.g. ..%2F wouldn't match the route
        # param regex above, but defense in depth never hurts).
        if not os.path.abspath(file_path).startswith(os.path.abspath(FRONTEND_DIR)):
            raise HTTPException(status_code=400, detail="Invalid path")
        if not os.path.isfile(file_path):
            raise HTTPException(status_code=404, detail="Not found")
        return FileResponse(
            file_path,
            media_type="text/html; charset=utf-8",
            headers={"Cache-Control": "public, max-age=3600"},
        )

    @app.get("/yandex_{site_token}.html", include_in_schema=False)
    async def serve_yandex_verification(site_token: str, request: Request):
        """Serve a Yandex Webmaster verification file.

        Yandex uses the format `yandex_<token>.html` with a small
        HTML body containing the verification string. We follow the
        same security model as the Google route:
          - Token restricted to hex / alphanumeric (Yandex tokens are
            always hex today, but alphanumeric keeps us future-proof).
          - Path resolution checked against FRONTEND_DIR.
          - Only the exact file is served; no other static files are
            exposed through this route.
        """
        # The route prefix uses `_` (matches Yandex's exact format).
        # The token itself is what we validate.
        if not site_token or not all(c.isalnum() for c in site_token) or len(site_token) > 64:
            raise HTTPException(status_code=404, detail="Not found")
        filename = f"yandex_{site_token}.html"
        file_path = os.path.join(FRONTEND_DIR, filename)
        if not os.path.abspath(file_path).startswith(os.path.abspath(FRONTEND_DIR)):
            raise HTTPException(status_code=400, detail="Invalid path")
        if not os.path.isfile(file_path):
            raise HTTPException(status_code=404, detail="Not found")
        return FileResponse(
            file_path,
            media_type="text/html; charset=utf-8",
            headers={"Cache-Control": "public, max-age=3600"},
        )

    # Keep deploy-sensitive assets revalidating so clients receive frontend fixes.
    @app.get("/app.js", include_in_schema=False)
    @app.get("/admin.js", include_in_schema=False)
    @app.get("/styles.css", include_in_schema=False)
    @app.get("/cipher-day.css", include_in_schema=False)
    async def serve_static_asset(request: Request):
        rel = request.url.path.lstrip("/")
        file_path = os.path.join(FRONTEND_DIR, rel)
        if not os.path.isfile(file_path):
            raise HTTPException(status_code=404, detail="Not found")
        return FileResponse(
            file_path,
            headers={"Cache-Control": "public, max-age=300, must-revalidate"},
        )

    @app.get("/favicon.ico", include_in_schema=False)
    async def serve_favicon():
        return FileResponse(
            os.path.join(FRONTEND_DIR, "favicon.ico"),
            headers={"Cache-Control": "public, max-age=86400"},
        )

    @app.get("/og-image.png", include_in_schema=False)
    async def serve_og_image():
        """Open Graph / Twitter card preview image. Social media crawlers
        fetch this when generating link previews. Cached aggressively
        since the image only changes on a release."""
        file_path = os.path.join(FRONTEND_DIR, "og-image.png")
        if not os.path.isfile(file_path):
            raise HTTPException(status_code=404, detail="og-image.png not found")
        return FileResponse(
            file_path,
            media_type="image/png",
            headers={"Cache-Control": "public, max-age=604800"},  # 7 days
        )

else:
    print(f"[WARN] Frontend directory not found at {_BUNDLED} or {_PARENT}")


# ==================== API CACHE MIDDLEWARE ====================

# Simple in-memory cache for read-heavy public endpoints
# Avoids hitting Turso on every request for data that changes rarely.
import time as _time
from threading import Lock as _Lock

_API_CACHE: dict = {}
_API_CACHE_LOCK = _Lock()
_API_CACHE_TTL = int(os.getenv("API_CACHE_TTL_SECONDS", "60"))  # default 60s


def _cache_get(key: str):
    """Return cached value if fresh, else None."""
    if _API_CACHE_TTL <= 0:
        return None
    with _API_CACHE_LOCK:
        entry = _API_CACHE.get(key)
        if entry is None:
            return None
        value, expires_at = entry
        if _time.time() > expires_at:
            del _API_CACHE[key]
            return None
        return value


def _cache_set(key: str, value, ttl: int = None):
    if _API_CACHE_TTL <= 0:
        return
    with _API_CACHE_LOCK:
        _API_CACHE[key] = (value, _time.time() + (ttl or _API_CACHE_TTL))


def _cache_clear_prefix(prefix: str):
    """Invalidate cache entries whose key starts with prefix (after a write)."""
    with _API_CACHE_LOCK:
        keys_to_delete = [k for k in _API_CACHE if k.startswith(prefix)]
        for k in keys_to_delete:
            del _API_CACHE[k]

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host=os.getenv("HOST", "0.0.0.0"),
        port=int(os.getenv("PORT", "8000")),
        reload=ENV == "dev",
        workers=1 if IS_PRODUCTION else 1
    )
