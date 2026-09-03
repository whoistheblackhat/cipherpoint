"""Security helpers: input validation, rate limiting, account lockout.

All functions are pure / thread-safe. The rate limiter and login-attempt
tracker live in process memory (Render free plan = single worker, so this
is sufficient). If you ever scale to multiple workers, swap the dicts for
Redis or a shared cache.
"""

from __future__ import annotations

import re
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Optional, Tuple

import bcrypt
import hmac

# ----------------------------------------------------------------------
# Input validation
# ----------------------------------------------------------------------

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")

# Reserved usernames (case-insensitive). These are blocked at signup so
# nobody can impersonate system accounts.
RESERVED_USERNAMES = frozenset({
    "admin", "administrator", "root", "system", "support",
    "cipherpoint", "cipher", "mod", "moderator", "staff", "official",
    "telegram", "bot", "null", "undefined", "api", "help",
})

# Per-IP and per-user rolling window for sensitive endpoints.
# Key: bucket identifier ("ip:1.2.3.4", "user:5", "otp:chat:123")
# Value: deque[float] of timestamps
_rate_buckets: dict[str, deque] = defaultdict(deque)
_rate_lock = threading.Lock()


def is_valid_username(username: str) -> Tuple[bool, str]:
    """Returns (ok, reason)."""
    if not username:
        return False, "Username is required"
    if len(username) < 3:
        return False, "Username must be at least 3 characters"
    if len(username) > 32:
        return False, "Username must be at most 32 characters"
    if not USERNAME_RE.match(username):
        return False, "Username may only contain letters, digits, '.', '_' and '-'"
    if username.lower() in RESERVED_USERNAMES:
        return False, "That username is reserved"
    return True, ""


def is_valid_email(email: str) -> Tuple[bool, str]:
    """Returns (ok, reason). Email must be lowercase already."""
    if not email:
        return False, "Email is required"
    if len(email) > 254:
        return False, "Email is too long"
    if not EMAIL_RE.match(email):
        return False, "Email format is invalid"
    return True, ""


def password_strength_errors(password: str) -> list[str]:
    """Returns a list of human-readable problems. Empty list = ok."""
    errors: list[str] = []
    if not password:
        errors.append("Password is required")
        return errors
    if len(password) < 8:
        errors.append("Password must be at least 8 characters")
    if len(password) > 128:
        errors.append("Password must be at most 128 characters")
    if not re.search(r"[A-Za-z]", password):
        errors.append("Password must contain at least one letter")
    if not re.search(r"\d", password):
        errors.append("Password must contain at least one digit")
    # Reject the most common weak passwords outright.
    COMMON = {
        "password", "password1", "password123", "12345678", "123456789",
        "qwerty", "qwerty123", "letmein", "iloveyou", "admin123",
        "welcome", "monkey", "dragon", "11111111", "00000000",
        "abc123", "123abc", "passw0rd",
    }
    if password.lower() in COMMON:
        errors.append("Password is too common")
    return errors


# ----------------------------------------------------------------------
# Bcrypt helpers with explicit cost factor
# ----------------------------------------------------------------------

_BCRYPT_ROUNDS = 12  # explicit so cost is auditable, not library default


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=_BCRYPT_ROUNDS)).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    if not plain_password or not hashed_password:
        return False
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
    except (ValueError, TypeError):
        return False


# ----------------------------------------------------------------------
# Rate limiting (sliding window, per-bucket)
# ----------------------------------------------------------------------

def rate_limit_check(bucket: str, max_events: int, window_seconds: int) -> Tuple[bool, int]:
    """Record an event and return (allowed, retry_after_seconds).

    `bucket` is a free-form key such as "login_ip:1.2.3.4" or "otp:chat:123".
    `max_events` events are allowed per `window_seconds`.
    """
    now = time.time()
    with _rate_lock:
        q = _rate_buckets[bucket]
        # Drop old timestamps
        while q and (now - q[0]) > window_seconds:
            q.popleft()
        if len(q) >= max_events:
            retry = max(1, int(window_seconds - (now - q[0])))
            return False, retry
        q.append(now)
        return True, 0


def rate_limit_reset(bucket: str) -> None:
    """Clear a bucket (e.g. after a successful login)."""
    with _rate_lock:
        _rate_buckets.pop(bucket, None)


# ----------------------------------------------------------------------
# Account lockout (persistent in DB, time-based)
# ----------------------------------------------------------------------

LOGIN_MAX_ATTEMPTS = 5
LOGIN_LOCKOUT_MINUTES = 15
LOGIN_ATTEMPT_RESET_MINUTES = 30  # reset counter after this much idle time


def is_account_locked(user, now: Optional[datetime] = None) -> Tuple[bool, int]:
    """Returns (is_locked, seconds_remaining)."""
    if now is None:
        now = datetime.utcnow()
    locked_until = getattr(user, "locked_until", None)
    if not locked_until:
        return False, 0
    if locked_until <= now:
        return False, 0
    remaining = int((locked_until - now).total_seconds())
    return True, remaining


def record_failed_login(user) -> None:
    """Increment counter, lock if threshold exceeded."""
    now = datetime.utcnow()
    last_failed = getattr(user, "last_failed_login_at", None)
    failed = int(getattr(user, "failed_login_count", 0) or 0)

    # If the user hasn't tried in a while, reset the counter so they get a
    # fresh budget of attempts.
    if last_failed and (now - last_failed).total_seconds() > LOGIN_ATTEMPT_RESET_MINUTES * 60:
        failed = 0

    failed += 1
    user.failed_login_count = failed
    user.last_failed_login_at = now

    if failed >= LOGIN_MAX_ATTEMPTS:
        user.locked_until = now + timedelta(minutes=LOGIN_LOCKOUT_MINUTES)


def record_successful_login(user) -> None:
    user.failed_login_count = 0
    user.locked_until = None
    user.last_failed_login_at = None


# ----------------------------------------------------------------------
# Constant-time compares
# ----------------------------------------------------------------------

def constant_time_eq(a: str, b: str) -> bool:
    """Constant-time string comparison. Returns False on length mismatch
    without leaking length via early-exit timing."""
    if a is None or b is None:
        return False
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))
