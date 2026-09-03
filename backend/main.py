from fastapi import FastAPI, Depends, HTTPException, Header, UploadFile, File, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
import jwt
import bcrypt
import os
import re
import secrets
import tempfile
import shutil
import threading
import time
import requests
from dotenv import load_dotenv
from typing import Optional
from html import escape as escape_html
from sqlalchemy import text

from database import init_db, get_db, SessionLocal
from models import User, Challenge, SolvedChallenge, UnlockedHint, ChallengeReport, UserBan, Comment
from telegram_proxy import get_telegram_file, upload_media_to_channel, validate_media_duration, send_telegram_message, send_telegram_photo_with_buttons, start_admin_bot_polling, TELEGRAM_ADMIN_CHAT_ID, TELEGRAM_ADMIN_BOT_TOKEN, send_user_notification, TELEGRAM_REPORT_BOT_TOKEN, get_bot_health

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

ENV = os.getenv("ENV", "dev").lower()
IS_PRODUCTION = ENV == "production"

if IS_PRODUCTION and (not SECRET_KEY or SECRET_KEY.startswith("your-secret-key")):
    raise RuntimeError("SECRET_KEY must be set in production environment")

if not SECRET_KEY or SECRET_KEY.startswith("your-secret-key"):
    print("[WARN] Using insecure default SECRET_KEY. Set a real one in .env for production.")

TURNSTILE_SITE_KEY = os.getenv("SITE_KEY", "").strip()
TURNSTILE_SECRET_KEY = os.getenv("CLOUDFLARE_SECRET_KEY", "").strip()
TURNSTILE_ENABLED = os.getenv("TURNSTILE_ENABLED", "false").lower() == "true"


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

# Initialize FastAPI app
app = FastAPI(title="CipherPoint API", version="1.0.0")

# CORS Middleware
frontend_url = os.getenv("FRONTEND_URL", "").strip()
allowed_origins = [frontend_url] if frontend_url else ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Request models
class UserSignupRequest(BaseModel):
    username: str
    email: str
    password: str
    turnstile_token: str | None = None

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

class ChallengeCreateRequest(BaseModel):
    title: str
    category: str
    difficulty: str
    description: str
    correct_flag: str
    points_reward: int
    hint_1: str
    hint_1_cost: int = 10
    hint_2: Optional[str] = None
    hint_2_cost: int = 20

    class Config:
        extra = "allow"

class CommunityChallengeCreateRequest(BaseModel):
    title: str
    category: str
    difficulty: str
    description: str
    correct_flag: str
    points_reward: int = 100
    hint_1: Optional[str] = None
    hint_1_cost: int = 10
    hint_2: Optional[str] = None
    hint_2_cost: int = 20
    disclaimer_accepted: bool = False
    tags: Optional[str] = ""

    class Config:
        extra = "allow"

class ChallengeReportRequest(BaseModel):
    reason: str
    details: str = ""

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
    combined = " ".join([
        payload.title or "",
        payload.category or "",
        payload.description or "",
        payload.correct_flag or "",
        payload.tags or "",
    ])
    if not payload.disclaimer_accepted:
        raise HTTPException(status_code=400, detail="You must accept the platform disclaimer before publishing a community challenge.")
    if is_sensitive_identity_content(combined):
        raise HTTPException(status_code=400, detail="Personal identity or private data is not allowed on this platform.")


COMMUNITY_CTF_WEEKLY_LIMIT = int(os.getenv("COMMUNITY_CTF_WEEKLY_LIMIT", "2"))
COMMUNITY_CTF_EXPIRY_DAYS = int(os.getenv("COMMUNITY_CTF_EXPIRY_DAYS", "7"))


def check_and_reset_weekly_quota(user: User):
    """Reset quota if a week has passed since last reset."""
    now = datetime.utcnow()
    reset_at = getattr(user, "weekly_reset_at", None)
    if not reset_at or now >= reset_at:
        user.weekly_challenges_used = 0
        user.weekly_reset_at = now + timedelta(days=7)


def enforce_community_quota(user: User):
    """Raise 429 if user has hit the weekly community CTF creation limit."""
    check_and_reset_weekly_quota(user)
    if (user.weekly_challenges_used or 0) >= COMMUNITY_CTF_WEEKLY_LIMIT:
        retry_after = max(0, int((user.weekly_reset_at - datetime.utcnow()).total_seconds()))
        days_left = max(1, retry_after // 86400)
        raise HTTPException(
            status_code=429,
            detail=f"You've reached your weekly limit of {COMMUNITY_CTF_WEEKLY_LIMIT} community CTFs. Quota resets in ~{days_left} day(s)."
        )


def ensure_admin_user():
    db = SessionLocal()
    try:
        existing = db.query(User).filter(User.username == "admin").first()
        if existing:
            if not existing.is_admin:
                existing.is_admin = True
                db.commit()
            return

        db.add(User(
            username="admin",
            email="admin@cipherpoint.com",
            password_hash=hash_password("admin123"),
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
_is_primary_worker = _worker_id in ("0", "primary", "1")


def purge_expired_community_challenges():
    """Delete community challenges older than COMMUNITY_CTF_EXPIRY_DAYS along with their comments and hints."""
    db = SessionLocal()
    try:
        cutoff = datetime.utcnow() - timedelta(days=COMMUNITY_CTF_EXPIRY_DAYS)
        expired = db.query(Challenge).filter(
            Challenge.is_community == True,
            Challenge.created_at < cutoff,
            Challenge.status != "removed"
        ).all()

        if not expired:
            return 0

        expired_ids = [c.id for c in expired]
        for c in expired:
            print(f"[EXPIRY] Purging community CTF #{c.id} '{c.title}' (created {c.created_at})")

        deleted_comments = db.query(Comment).filter(Comment.challenge_id.in_(expired_ids)).delete(synchronize_session=False)
        deleted_hints = db.query(UnlockedHint).filter(UnlockedHint.challenge_id.in_(expired_ids)).delete(synchronize_session=False)
        deleted_solves = db.query(SolvedChallenge).filter(SolvedChallenge.challenge_id.in_(expired_ids)).delete(synchronize_session=False)
        deleted_reports = db.query(ChallengeReport).filter(ChallengeReport.challenge_id.in_(expired_ids)).delete(synchronize_session=False)
        db.query(Challenge).filter(Challenge.id.in_(expired_ids)).delete(synchronize_session=False)

        db.commit()
        print(f"[EXPIRY] Purged {len(expired_ids)} challenges, {deleted_comments} comments, {deleted_hints} hints, {deleted_solves} solves, {deleted_reports} reports")

        if TELEGRAM_ADMIN_CHAT_ID and len(expired) > 0:
            try:
                send_telegram_message(
                    TELEGRAM_ADMIN_CHAT_ID,
                    f"🧹 <b>Auto-Purge Complete</b>\n\n"
                    f"Expired community CTFs (> {COMMUNITY_CTF_EXPIRY_DAYS} days): <b>{len(expired_ids)}</b>\n"
                    f"Cascade-deleted comments: {deleted_comments}\n"
                    f"Cascade-deleted hints: {deleted_hints}\n"
                    f"Cascade-deleted solves: {deleted_solves}\n"
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

def hash_password(password: str) -> str:
    """Hash password using bcrypt"""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify hashed password"""
    return bcrypt.checkpw(plain_password.encode(), hashed_password.encode())

def create_access_token(data: dict):
    """Create JWT access token"""
    to_encode = data.copy()
    if 'sub' in to_encode and not isinstance(to_encode['sub'], str):
        to_encode['sub'] = str(to_encode['sub'])
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(authorization: Optional[str] = Header(None)):
    """Verify JWT token from Authorization header"""
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing authorization header")
    
    try:
        scheme, token = authorization.split()
        if scheme.lower() != "bearer":
            raise HTTPException(status_code=401, detail="Invalid authorization scheme")
        
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
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


def ensure_user_not_banned(user_id: int, db: Session):
    if db.query(UserBan).filter(UserBan.user_id == user_id).first():
        raise HTTPException(status_code=403, detail="Your account has been suspended.")


class CommentCreateRequest(BaseModel):
    body: str


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
            "user_id": c.user_id,
            "username": users.get(c.user_id, "unknown"),
            "body": c.body,
            "parent_id": c.parent_id,
            "created_at": c.created_at,
            "replies": [
                {
                    "id": r.id,
                    "challenge_id": r.challenge_id,
                    "user_id": r.user_id,
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
    user_id: int = Depends(verify_token),
    db: Session = Depends(get_db)
):
    """Post a new comment or reply on a challenge."""
    ensure_user_not_banned(user_id, db)
    challenge = db.query(Challenge).filter(Challenge.id == challenge_id).first()
    if not challenge:
        raise HTTPException(status_code=404, detail="Challenge not found")

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

    new_comment = Comment(challenge_id=challenge_id, user_id=user_id, body=body, parent_id=parent_id)
    db.add(new_comment)
    db.commit()
    db.refresh(new_comment)

    author = db.query(User).filter(User.id == user_id).first()
    return {
        "id": new_comment.id,
        "challenge_id": new_comment.challenge_id,
        "user_id": new_comment.user_id,
        "username": author.username if author else "unknown",
        "body": new_comment.body,
        "parent_id": new_comment.parent_id,
        "created_at": new_comment.created_at,
    }


# ==================== AUTH ROUTES ====================

@app.post("/api/auth/signup")
def signup(payload: UserSignupRequest, request: Request, db: Session = Depends(get_db)):
    """User signup endpoint"""
    username = payload.username.strip()
    email = payload.email.strip().lower()
    password = payload.password
    if not username or not email or not password:
        raise HTTPException(status_code=400, detail="Username, email and password are required")

    if TURNSTILE_SECRET_KEY and TURNSTILE_ENABLED:
        remote_ip = request.client.host if request.client else None
        if not verify_turnstile_token(payload.turnstile_token, remote_ip):
            raise HTTPException(status_code=403, detail="Turnstile verification failed. Please complete the security check.")

    existing_user = db.query(User).filter(
        (User.username == username) | (User.email == email)
    ).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username or email already exists")
    hashed_password = hash_password(password)
    new_user = User(
        username=username,
        email=email,
        password_hash=hashed_password,
        coins=50,
        rank_points=0,
        is_admin=False,
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    access_token = create_access_token(data={"sub": new_user.id})
    return {
        "id": new_user.id,
        "username": new_user.username,
        "email": new_user.email,
        "coins": new_user.coins,
        "rank_points": new_user.rank_points,
        "is_admin": bool(new_user.is_admin),
        "access_token": access_token,
        "token_type": "bearer"
    }

@app.post("/api/auth/login")
def login(payload: UserLoginRequest, request: Request, db: Session = Depends(get_db)):
    """User login endpoint"""
    if TURNSTILE_SECRET_KEY and TURNSTILE_ENABLED:
        remote_ip = request.client.host if request.client else None
        if not verify_turnstile_token(payload.turnstile_token, remote_ip):
            raise HTTPException(status_code=403, detail="Turnstile verification failed. Please complete the security check.")

    user = db.query(User).filter(User.username == payload.username.strip()).first()
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    ensure_user_not_banned(user.id, db)
    access_token = create_access_token(data={"sub": user.id})
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

OTP_REQUEST_WINDOW_SECONDS = 60
OTP_VALID_SECONDS = 300
OTP_MAX_ATTEMPTS = 3


def _generate_login_otp() -> str:
    return f"{secrets.randbelow(1000000):06d}"


@app.post("/api/auth/login/otp/request")
def login_otp_request(payload: OtpLoginRequest, request: Request, db: Session = Depends(get_db)):
    """Send a 6-digit OTP to the given Telegram chat_id for passwordless login."""
    chat_id = (payload.chat_id or "").strip()
    if not chat_id or not chat_id.lstrip("-").isdigit():
        raise HTTPException(status_code=400, detail="A valid Telegram chat ID is required")

    if TURNSTILE_SECRET_KEY and TURNSTILE_ENABLED:
        remote_ip = request.client.host if request.client else None
        if not verify_turnstile_token(payload.turnstile_token, remote_ip):
            raise HTTPException(status_code=403, detail="Turnstile verification failed. Please complete the security check.")

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
    if not hasattr(user, "login_otp_requested_at"):
        try:
            db.execute(text("ALTER TABLE users ADD COLUMN login_otp_requested_at DATETIME"))
        except Exception:
            pass
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
def login_otp_verify(payload: OtpVerifyRequest, db: Session = Depends(get_db)):
    """Verify the OTP and issue a JWT for the linked user."""
    chat_id = (payload.chat_id or "").strip()
    otp = (payload.otp or "").strip()
    if not chat_id or not otp:
        raise HTTPException(status_code=400, detail="Chat ID and OTP are required")

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

    if otp != stored_code:
        user.login_otp_attempts = attempts + 1
        remaining = OTP_MAX_ATTEMPTS - user.login_otp_attempts
        db.commit()
        raise HTTPException(status_code=400, detail=f"Incorrect OTP. {remaining} attempt(s) remaining.")

    user.login_otp_code = None
    user.login_otp_expires = None
    user.login_otp_attempts = 0
    if hasattr(user, "login_otp_requested_at"):
        user.login_otp_requested_at = None
    db.commit()

    access_token = create_access_token(data={"sub": user.id})
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


@app.get("/api/auth/me")
def get_current_user(user_id: int = Depends(verify_token), db: Session = Depends(get_db)):
    """Get current user profile"""
    user = db.query(User).filter(User.id == user_id).first()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    ensure_user_not_banned(user_id, db)
    solved_count = db.query(SolvedChallenge).filter(SolvedChallenge.user_id == user_id).count()
    solved_challenges = db.query(SolvedChallenge).filter(SolvedChallenge.user_id == user_id).all()
    challenge_ids = [entry.challenge_id for entry in solved_challenges]
    
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "coins": user.coins,
        "rank_points": user.rank_points,
        "is_admin": bool(user.is_admin),
        "solved_count": solved_count,
        "solved_challenges": challenge_ids,
        "created_at": user.created_at
    }

@app.get("/api/profile")
def get_profile(user_id: int = Depends(verify_token), db: Session = Depends(get_db)):
    """Protected profile endpoint"""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    ensure_user_not_banned(user_id, db)
    solved = db.query(SolvedChallenge).filter(SolvedChallenge.user_id == user_id).all()
    solved_titles = []
    for entry in solved:
        challenge = db.query(Challenge).filter(Challenge.id == entry.challenge_id).first()
        if challenge:
            solved_titles.append({"id": challenge.id, "title": challenge.title, "difficulty": challenge.difficulty})

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
        "rank_points": user.rank_points,
        "solved_count": len(solved),
         "solved_challenges": solved_titles,
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

from pydantic import BaseModel

class ProfileUpdate(BaseModel):
    username: str | None = None
    bio: str | None = None
    avatar_url: str | None = None

@app.put("/api/profile")
def update_profile(update: ProfileUpdate, user_id: int = Depends(verify_token), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if update.username and update.username != user.username:
        existing = db.query(User).filter(User.username == update.username).first()
        if existing and existing.id != user_id:
            raise HTTPException(status_code=400, detail="Username already taken")
        user.username = update.username

    if update.bio is not None:
        user.bio = update.bio

    if update.avatar_url is not None:
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
        "telegram_chat_id": user.telegram_chat_id,
        "telegram_notifications": user.telegram_notifications
    }

class TelegramConnectRequest(BaseModel):
    chat_id: str
    enabled: bool | None = True

class TelegramSettingsRequest(BaseModel):
    enabled: bool | None = None
    chat_id: str | None = None

class PasswordResetRequest(BaseModel):
    username: str

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
        raise HTTPException(status_code=400, detail="Current password is incorrect")

    if len(payload.new_password) < 6:
        raise HTTPException(status_code=400, detail="New password must be at least 6 characters")

    user.password_hash = hash_password(payload.new_password)
    db.commit()

    if user.telegram_chat_id and user.telegram_notifications:
        send_user_notification(
            user.telegram_chat_id,
            f"🔐 <b>Password updated</b>\n\nHello <b>{escape_html(user.username)}</b>, your CipherPoint password was successfully changed."
        )

    return {"message": "Password updated successfully"}

class NotificationSettingsRequest(BaseModel):
    notify_new_challenges: bool | None = None
    notify_comments: bool | None = None
    notify_mentions: bool | None = None

@app.put("/api/settings/notifications")
def update_notification_settings(payload: NotificationSettingsRequest, user_id: int = Depends(verify_token), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

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

    db.query(SolvedChallenge).filter(SolvedChallenge.user_id == user_id).delete(synchronize_session=False)
    db.query(UnlockedHint).filter(UnlockedHint.user_id == user_id).delete(synchronize_session=False)
    db.query(ChallengeReport).filter(ChallengeReport.reporter_id == user_id).delete(synchronize_session=False)
    db.query(Comment).filter(Comment.user_id == user_id).delete(synchronize_session=False)

    db.delete(user)
    db.commit()

    return {"message": "Account deleted successfully"}


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
        user.telegram_chat_id = payload.chat_id

    db.commit()
    db.refresh(user)
    return {
        "telegram_chat_id": user.telegram_chat_id,
        "telegram_notifications": user.telegram_notifications
    }


@app.post("/api/auth/password-reset/request")
def request_password_reset(payload: PasswordResetRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == payload.username).first()
    if not user:
        return {"message": "If the account exists, a reset link has been sent"}

    if not user.telegram_chat_id or not TELEGRAM_REPORT_BOT_TOKEN:
        return {"message": "If the account exists, a reset link has been sent"}

    import secrets
    token = secrets.token_urlsafe(32)
    setattr(user, "reset_token", token)
    from datetime import datetime, timedelta
    setattr(user, "reset_token_expires", datetime.utcnow() + timedelta(minutes=30))
    db.commit()

    message = (
        f"🔐 <b>Password Reset Request</b>\n\n"
        f"Hello <b>{escape_html(user.username)}</b>,\n\n"
        f"Use this token to reset your password (valid for 30 minutes):\n\n"
        f"<code>{token}</code>\n\n"
        f"If you did not request this, please secure your account immediately."
    )
    send_user_notification(user.telegram_chat_id, message)

    return {"message": "If the account exists, a reset link has been sent"}


@app.post("/api/auth/password-reset/confirm")
def confirm_password_reset(payload: PasswordResetConfirm, db: Session = Depends(get_db)):
    from datetime import datetime
    user = db.query(User).filter(User.reset_token == payload.reset_token).first()
    if not user:
        raise HTTPException(status_code=400, detail="Invalid or expired token")

    expires = getattr(user, "reset_token_expires", None)
    if not expires or expires < datetime.utcnow():
        raise HTTPException(status_code=400, detail="Invalid or expired token")

    if len(payload.new_password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")

    user.password_hash = hash_password(payload.new_password)
    setattr(user, "reset_token", None)
    setattr(user, "reset_token_expires", None)
    db.commit()

    if user.telegram_chat_id:
        send_user_notification(
            user.telegram_chat_id,
            f"✅ <b>Password updated</b>\n\nYour CipherPoint password was successfully changed."
        )

    return {"message": "Password reset successful"}

# ==================== CHALLENGES ROUTES ====================

@app.get("/api/challenges")
def get_all_challenges(db: Session = Depends(get_db)):
    """Get all approved challenges with metadata"""
    challenges = db.query(Challenge).filter(Challenge.status.notin_(["rejected", "removed"])).all()
    
    result = []
    for challenge in challenges:
        solved_count = db.query(SolvedChallenge).filter(SolvedChallenge.challenge_id == challenge.id).count()
        result.append({
            "id": challenge.id,
            "title": challenge.title,
            "category": challenge.category,
            "difficulty": challenge.difficulty,
            "description": challenge.description,
            "telegram_file_id": challenge.telegram_file_id,
            "points_reward": challenge.points_reward,
            "solved_count": solved_count,
            "status": challenge.status,
            "is_community": bool(challenge.is_community),
            "created_by": challenge.created_by,
            "created_at": challenge.created_at
        })
    
    return result


@app.get("/api/challenges/community")
def get_community_challenges(db: Session = Depends(get_db)):
    """Get public community-run challenges."""
    challenges = db.query(Challenge).filter((Challenge.is_community == True) & (Challenge.status.notin_(["rejected", "removed"]))).all()
    result = []
    for challenge in challenges:
        solved_count = db.query(SolvedChallenge).filter(SolvedChallenge.challenge_id == challenge.id).count()
        result.append({
            "id": challenge.id,
            "title": challenge.title,
            "category": challenge.category,
            "difficulty": challenge.difficulty,
            "description": challenge.description,
            "telegram_file_id": challenge.telegram_file_id,
            "points_reward": challenge.points_reward,
            "solved_count": solved_count,
            "status": challenge.status,
            "created_by": challenge.created_by,
            "tags": challenge.tags or "",
            "created_at": challenge.created_at,
        })
    return result

@app.get("/api/challenges/{challenge_id}")
def get_challenge_details(challenge_id: int, db: Session = Depends(get_db)):
    """Get detailed view of a challenge (WITHOUT flag or hints)"""
    challenge = db.query(Challenge).filter(Challenge.id == challenge_id).first()
    
    if not challenge:
        raise HTTPException(status_code=404, detail="Challenge not found")
    
    solved_count = db.query(SolvedChallenge).filter(SolvedChallenge.challenge_id == challenge_id).count()
    
    return {
        "id": challenge.id,
        "title": challenge.title,
        "category": challenge.category,
        "difficulty": challenge.difficulty,
        "description": challenge.description,
        "telegram_file_id": challenge.telegram_file_id,
        "points_reward": challenge.points_reward,
        "hint_1": challenge.hint_1,
        "hint_2": challenge.hint_2,
        "hint_1_cost": challenge.hint_1_cost,
        "hint_2_cost": challenge.hint_2_cost,
        "tags": challenge.tags,
        "created_by": challenge.created_by,
        "is_community": bool(challenge.is_community),
        "status": challenge.status,
        "solved_count": solved_count,
        "created_at": challenge.created_at
    }

@app.post("/api/challenges/create")
def create_challenge(
    payload: ChallengeCreateRequest,
    user: User = Depends(get_current_admin_user),
    db: Session = Depends(get_db)
):
    """Create new challenge (Admin only). Accepts JSON payload."""
    title = payload.title.strip()
    category = payload.category.strip()
    difficulty = payload.difficulty.strip()
    description = payload.description.strip()
    telegram_file_id = getattr(payload, "telegram_file_id", "").strip()
    correct_flag = payload.correct_flag.strip()

    if not all([title, category, difficulty, description, telegram_file_id, correct_flag]):
        raise HTTPException(status_code=400, detail="All challenge fields are required")

    if payload.points_reward < 0:
        raise HTTPException(status_code=400, detail="points_reward must be >= 0")
    if payload.hint_1_cost < 0 or payload.hint_2_cost < 0:
        raise HTTPException(status_code=400, detail="Hint costs must be >= 0")

    new_challenge = Challenge(
        title=title,
        category=category,
        difficulty=difficulty,
        description=description,
        telegram_file_id=telegram_file_id,
        correct_flag=correct_flag,
        points_reward=payload.points_reward,
        hint_1=payload.hint_1.strip() if payload.hint_1 else None,
        hint_1_cost=payload.hint_1_cost,
        hint_2=payload.hint_2.strip() if payload.hint_2 else None,
        hint_2_cost=payload.hint_2_cost,
        created_by=user.id,
        status="approved",
        is_community=False,
        disclaimer_accepted=True,
    )

    db.add(new_challenge)
    db.commit()
    db.refresh(new_challenge)

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
    enforce_community_quota(user)

    validate_community_submission(payload)

    title = payload.title.strip()
    category = payload.category.strip()
    difficulty = payload.difficulty.strip()
    description = payload.description.strip()
    telegram_file_id = getattr(payload, "telegram_file_id", "").strip()
    correct_flag = payload.correct_flag.strip()

    if not all([title, category, difficulty, description, telegram_file_id, correct_flag]):
        raise HTTPException(status_code=400, detail="All challenge fields are required")

    if payload.points_reward < 0:
        raise HTTPException(status_code=400, detail="points_reward must be >= 0")
    if payload.hint_1_cost < 0 or payload.hint_2_cost < 0:
        raise HTTPException(status_code=400, detail="Hint costs must be >= 0")

    new_challenge = Challenge(
        title=title,
        category=category,
        difficulty=difficulty,
        description=description,
        telegram_file_id=telegram_file_id,
        correct_flag=correct_flag,
        points_reward=payload.points_reward,
        hint_1=payload.hint_1.strip() if payload.hint_1 else None,
        hint_1_cost=payload.hint_1_cost,
        hint_2=payload.hint_2.strip() if payload.hint_2 else None,
        hint_2_cost=payload.hint_2_cost,
        created_by=user_id,
        status="approved",
        is_community=True,
        disclaimer_accepted=payload.disclaimer_accepted,
        tags=(payload.tags or "").strip(),
    )

    db.add(new_challenge)
    db.flush()

    user.weekly_challenges_used = (user.weekly_challenges_used or 0) + 1
    if not getattr(user, "weekly_reset_at", None):
        user.weekly_reset_at = datetime.utcnow() + timedelta(days=7)
    db.commit()
    db.refresh(new_challenge)

    remaining = max(0, COMMUNITY_CTF_WEEKLY_LIMIT - user.weekly_challenges_used)

    return {
        "id": new_challenge.id,
        "title": new_challenge.title,
        "message": "Community challenge published successfully!",
        "is_community": True,
        "status": new_challenge.status,
        "quota": {
            "used": user.weekly_challenges_used,
            "limit": COMMUNITY_CTF_WEEKLY_LIMIT,
            "remaining": remaining,
            "resets_at": user.weekly_reset_at.isoformat() if user.weekly_reset_at else None
        }
    }


@app.post("/api/challenges/{challenge_id}/report")
def report_challenge(
    challenge_id: int,
    payload: ChallengeReportRequest,
    reporter_id: int = Depends(verify_token),
    db: Session = Depends(get_db)
):
    """Allow users to flag a challenge for moderation review."""
    try:
        ensure_user_not_banned(reporter_id, db)
        challenge = db.query(Challenge).filter(Challenge.id == challenge_id).first()
        if not challenge:
            raise HTTPException(status_code=404, detail="Challenge not found")

        existing = db.query(ChallengeReport).filter(
            (ChallengeReport.challenge_id == challenge_id) &
            (ChallengeReport.reporter_id == reporter_id)
        ).first()
        if existing:
            return {"message": "You already reported this challenge.", "status": "already_reported"}

        reason = payload.reason.strip()[:200]
        details = payload.details.strip()[:400]
        if not reason:
            raise HTTPException(status_code=400, detail="Report reason is required")

        report = ChallengeReport(
            challenge_id=challenge_id,
            reporter_id=reporter_id,
            reason=reason,
            details=details,
            status="open",
        )
        challenge.report_count += 1
        db.add(report)
        db.commit()

        reporter = db.query(User).filter(User.id == reporter_id).first()
        reporter_name = reporter.username if reporter else "Unknown"

        print(f"[REPORT] Challenge #{challenge_id} reported by {reporter_name}")
        print(f"[REPORT] Admin chat configured: {bool(TELEGRAM_ADMIN_CHAT_ID)}")
        print(f"[REPORT] Admin bot configured: {bool(TELEGRAM_ADMIN_BOT_TOKEN)}")

        if TELEGRAM_ADMIN_CHAT_ID:
            try:
                caption = (
                    f"🚨 <b>New Challenge Report</b>\n\n"
                    f"Challenge: #{challenge_id} - {challenge.title}\n"
                    f"Category: {challenge.category} | Difficulty: {challenge.difficulty}\n"
                    f"Reported by: {reporter_name}\n"
                    f"Reason: {reason}\n"
                    f"Details: {details}\n\n"
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
            except Exception as e:
                print(f"[REPORT] Telegram notification failed: {e}")
        else:
            print("⚠️ Report received but TELEGRAM_ADMIN_CHAT_ID not configured. Set it in .env to receive notifications.")

        return {"message": "Challenge reported successfully.", "status": "open", "report_id": report.id}
    except HTTPException:
        raise
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Report failed: {str(e)}")


@app.get("/api/moderation/reports")
def list_moderation_reports(admin_user: User = Depends(get_current_admin_user), db: Session = Depends(get_db)):
    """Return open reports that need moderator action."""
    reports = db.query(ChallengeReport).filter(ChallengeReport.status == "open").order_by(ChallengeReport.created_at.desc()).all()
    payload = []
    for report in reports:
        challenge = db.query(Challenge).filter(Challenge.id == report.challenge_id).first()
        reporter = db.query(User).filter(User.id == report.reporter_id).first()
        payload.append({
            "id": report.id,
            "challenge_id": report.challenge_id,
            "challenge_title": challenge.title if challenge else "Unknown challenge",
            "reporter": reporter.username if reporter else "unknown",
            "reason": report.reason,
            "details": report.details,
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
    if action == "reject" and challenge:
        challenge.status = "rejected"
    elif action == "ban":
        if challenge:
            challenge.status = "removed"
        existing_ban = db.query(UserBan).filter(UserBan.user_id == report.reporter_id).first()
        if not existing_ban:
            db.add(UserBan(user_id=report.reporter_id, reason=payload.reason or "Challenge report violation", banned_by=admin_user.id))

    report.status = "resolved"
    report.resolved_at = datetime.utcnow()
    report.resolved_by = admin_user.id
    db.commit()
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
        challenge.title = payload.title.strip()
    if payload.description is not None:
        challenge.description = payload.description.strip()
    if payload.hint_1 is not None:
        challenge.hint_1 = payload.hint_1.strip() or None
    if payload.hint_2 is not None:
        challenge.hint_2 = payload.hint_2.strip() or None
    if payload.hint_1_cost is not None:
        challenge.hint_1_cost = max(0, payload.hint_1_cost)
    if payload.hint_2_cost is not None:
        challenge.hint_2_cost = max(0, payload.hint_2_cost)
    if payload.points_reward is not None:
        challenge.points_reward = max(0, payload.points_reward)
    if payload.tags is not None:
        challenge.tags = payload.tags.strip()

    db.commit()
    db.refresh(challenge)
    return {"message": "Challenge updated successfully.", "id": challenge.id}


# ==================== HINT ROUTES ====================

@app.post("/api/hints/unlock")
def unlock_hint(payload: HintRequest, user_id: int = Depends(verify_token), db: Session = Depends(get_db)):
    """Unlock a hint by paying coins"""
    challenge_id = payload.challenge_id
    hint_number = payload.hint_number
    challenge = db.query(Challenge).filter(Challenge.id == challenge_id).first()
    if not challenge:
        raise HTTPException(status_code=404, detail="Challenge not found")
    if hint_number not in [1, 2]:
        raise HTTPException(status_code=400, detail="Invalid hint number")
    hint_cost = challenge.hint_1_cost if hint_number == 1 else challenge.hint_2_cost
    hint_text = challenge.hint_1 if hint_number == 1 else challenge.hint_2
    if not hint_text:
        raise HTTPException(status_code=404, detail="Hint not available")
    already_unlocked = db.query(UnlockedHint).filter(
        (UnlockedHint.user_id == user_id) &
        (UnlockedHint.challenge_id == challenge_id) &
        (UnlockedHint.hint_number == hint_number)
    ).first()
    if already_unlocked:
        return {
            "hint_number": hint_number,
            "hint_text": hint_text,
            "message": "Hint already unlocked"
        }
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.coins < hint_cost:
        raise HTTPException(status_code=400, detail=f"Insufficient coins. Need {hint_cost}, have {user.coins}")
    user.coins -= hint_cost
    new_unlocked_hint = UnlockedHint(user_id=user_id, challenge_id=challenge_id, hint_number=hint_number)
    db.add(new_unlocked_hint)
    db.commit()
    return {
        "hint_number": hint_number,
        "hint_text": hint_text,
        "cost": hint_cost,
        "remaining_coins": user.coins,
        "message": "Hint unlocked successfully!"
    }

# ==================== SUBMISSION ROUTES ====================

@app.post("/api/challenges/submit")
def submit_flag(payload: FlagSubmitRequest, user_id: int = Depends(verify_token), db: Session = Depends(get_db)):
    """Submit a flag/answer for a challenge"""
    challenge_id = payload.challenge_id
    flag = payload.flag
    challenge = db.query(Challenge).filter(Challenge.id == challenge_id).first()
    if not challenge:
        raise HTTPException(status_code=404, detail="Challenge not found")
    already_solved = db.query(SolvedChallenge).filter(
        (SolvedChallenge.user_id == user_id) &
        (SolvedChallenge.challenge_id == challenge_id)
    ).first()
    if already_solved:
        return {"success": False, "message": "You already solved this challenge!"}
    if flag.strip().lower() == challenge.correct_flag.lower():
        user = db.query(User).filter(User.id == user_id).first()
        user.coins += challenge.points_reward
        user.rank_points += challenge.points_reward
        solved_challenge = SolvedChallenge(user_id=user_id, challenge_id=challenge_id)
        db.add(solved_challenge)
        db.commit()
        return {
            "success": True,
            "message": "Correct! Challenge solved!",
            "coins_earned": challenge.points_reward,
            "total_coins": user.coins,
            "rank_points": user.rank_points
        }
    return {"success": False, "message": "Incorrect flag. Try again!"}

# ==================== LEADERBOARD ROUTES ====================

@app.get("/api/leaderboard")
def get_leaderboard(limit: int = 100, db: Session = Depends(get_db)):
    """Get top users by rank points"""
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
            "user_id": user.id,
            "username": user.username,
            "rank_points": rank_points,
            "coins": coins,
            "solved_count": solved_count,
            "badges": badges,
            "is_admin": bool(user.is_admin),
        })

    return result

# ==================== FILE UPLOAD ROUTES ====================

@app.post("/api/upload/media")
async def upload_media(
    file: UploadFile = File(...),
    user_id: int = Depends(verify_token),
    db: Session = Depends(get_db)
):
    """Upload image/video to Telegram channel via bot pool with backpressure."""
    from telegram_proxy import UPLOAD_SEMAPHORE

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    ensure_user_not_banned(user_id, db)

    if not UPLOAD_SEMAPHORE.acquire(blocking=False):
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
            contents = await file.read()

            if len(contents) > size_limit:
                os.unlink(tmp_path)
                raise HTTPException(status_code=413, detail=f"File too large. Max size: {size_limit // (1024*1024)}MB")

            tmp_file.write(contents)
            tmp_file.flush()

        if file.content_type.startswith("video"):
            validate_media_duration(tmp_path, file.content_type)

        upload_result = upload_media_to_channel(tmp_path, file.content_type)

        return {
            "success": True,
            "file_id": upload_result["file_id"],
            "filename": file.filename,
            "content_type": file.content_type,
            "served_by_bot": upload_result.get("bot_token"),
            "message": "Media uploaded to Telegram successfully"
        }

    except HTTPException:
        raise
    except ValueError as e:
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise HTTPException(status_code=503, detail=f"Upload temporarily unavailable: {str(e)}")
    finally:
        UPLOAD_SEMAPHORE.release()


@app.get("/api/health/bots")
def bots_health(user_id: int = Depends(verify_token)):
    """Public health snapshot of all Telegram bots."""
    return {
        "bots": get_bot_health(),
        "upload_queue_capacity": int(os.getenv("MAX_CONCURRENT_UPLOADS", "20"))
    }


# ==================== MEDIA PROXY ROUTES ====================

@app.get("/api/media/{file_id}")
def get_media(file_id: str):
    """Proxy endpoint for Telegram media"""
    try:
        return get_telegram_file(file_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Media fetch failed: {str(e)}")

# ==================== HEALTH CHECK ====================

@app.get("/api/health")
def health_check():
    """Health check endpoint"""
    return {"status": "✅ CipherPoint API is running!"}

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

if os.path.isdir(FRONTEND_DIR):
    # Mount static assets (JS, CSS, images) at /static
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")

    # Root serves index.html (landing page)
    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    async def serve_index():
        return FileResponse(os.path.join(FRONTEND_DIR, "index.html"))

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
    async def serve_html_page(request: Request):
        """Serve any *.html file from the frontend directory."""
        filename = request.url.path.lstrip("/")
        file_path = os.path.join(FRONTEND_DIR, filename)
        # Security: ensure path is within FRONTEND_DIR (no path traversal)
        if not os.path.abspath(file_path).startswith(os.path.abspath(FRONTEND_DIR)):
            raise HTTPException(status_code=400, detail="Invalid path")
        if not os.path.isfile(file_path):
            raise HTTPException(status_code=404, detail="Page not found")
        return FileResponse(file_path)

    # Serve common static asset extensions
    @app.get("/app.js", include_in_schema=False)
    @app.get("/styles.css", include_in_schema=False)
    async def serve_static_asset(request: Request):
        filename = request.url.path.lstrip("/")
        file_path = os.path.join(FRONTEND_DIR, filename)
        if not os.path.abspath(file_path).startswith(os.path.abspath(FRONTEND_DIR)):
            raise HTTPException(status_code=400, detail="Invalid path")
        if not os.path.isfile(file_path):
            raise HTTPException(status_code=404, detail="Not found")
        return FileResponse(file_path, media_type=None)
else:
    print(f"[WARN] Frontend directory not found at {_BUNDLED} or {_PARENT}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host=os.getenv("HOST", "0.0.0.0"),
        port=int(os.getenv("PORT", "8000")),
        reload=ENV == "dev",
        workers=1 if IS_PRODUCTION else 1
    )
