import os
import requests
import json
import subprocess
import threading
import time as _time
import time
from datetime import datetime
from typing import List, Tuple, Optional
from dotenv import load_dotenv
from sqlalchemy.orm import Session
from fastapi.responses import StreamingResponse
from html import escape as escape_html
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor, as_completed

load_dotenv()

TELEGRAM_API_URL = "https://api.telegram.org"
TELEGRAM_BOT_TOKENS = [token.strip() for token in os.getenv("TELEGRAM_BOT_TOKENS", "").split(",") if token.strip()]
TELEGRAM_ADMIN_BOT_TOKEN = os.getenv("TELEGRAM_ADMIN_BOT_TOKEN", "").strip()
TELEGRAM_REPORT_BOT_TOKEN = os.getenv("REPORT_BOT_TOKEN", "").strip()
TELEGRAM_CHANNEL_ID = os.getenv("TELEGRAM_CHANNEL_ID", "")
TELEGRAM_ADMIN_CHAT_ID = os.getenv("TELEGRAM_ADMIN_CHAT_ID", "")

_BOT_INDEX = 0
_BOT_INDEX_LOCK = threading.Lock()

# Per-bot rate limiting: track last call time
_BOT_LAST_CALL = {}
_BOT_LOCKS = defaultdict(threading.Lock)
_BOT_FAILURE_COUNT = defaultdict(int)
_BOT_CIRCUIT_OPEN_UNTIL = {}

# Global upload semaphore to prevent thread explosion
UPLOAD_SEMAPHORE = threading.Semaphore(int(os.getenv("MAX_CONCURRENT_UPLOADS", "20")))
UPLOAD_EXECUTOR = ThreadPoolExecutor(
    max_workers=int(os.getenv("MAX_UPLOAD_WORKERS", "8")),
    thread_name_prefix="tgupload"
)


def _get_bot_tokens() -> List[str]:
    return TELEGRAM_BOT_TOKENS


def _is_bot_available(bot_token: str) -> bool:
    """Check if bot's circuit breaker is closed (not tripped)."""
    until = _BOT_CIRCUIT_OPEN_UNTIL.get(bot_token, 0)
    if until > time.time():
        return False
    return True


def _mark_bot_success(bot_token: str):
    _BOT_FAILURE_COUNT[bot_token] = 0
    _BOT_CIRCUIT_OPEN_UNTIL.pop(bot_token, None)


def _mark_bot_failure(bot_token: str):
    _BOT_FAILURE_COUNT[bot_token] = _BOT_FAILURE_COUNT.get(bot_token, 0) + 1
    if _BOT_FAILURE_COUNT[bot_token] >= 5:
        _BOT_CIRCUIT_OPEN_UNTIL[bot_token] = time.time() + 60
        print(f"[CIRCUIT] Bot {bot_token[:10]}... opened for 60s after {_BOT_FAILURE_COUNT[bot_token]} failures")


def _get_round_robin_bot() -> str:
    """Thread-safe round-robin with circuit breaker awareness."""
    global _BOT_INDEX
    tokens = _get_bot_tokens()
    if not tokens:
        raise ValueError("No Telegram bot tokens configured. Add TELEGRAM_BOT_TOKENS in .env")

    with _BOT_INDEX_LOCK:
        available = [t for t in tokens if _is_bot_available(t)]
        if not available:
            _BOT_CIRCUIT_OPEN_UNTIL.clear()
            available = tokens
        attempts = len(tokens)
        token = None
        for _ in range(attempts):
            candidate = tokens[_BOT_INDEX % len(tokens)]
            _BOT_INDEX += 1
            if _is_bot_available(candidate):
                token = candidate
                break
        if not token:
            token = available[0]
        return token


def _get_bot_token_for_file(file_id: str) -> str:
    """For downloads - try all bots (file_id is bot-specific in Telegram)."""
    tokens = _get_bot_tokens()
    if not tokens:
        raise ValueError("No Telegram bot tokens configured")
    return tokens[0]


def get_bot_health() -> dict:
    """Public health snapshot for /api/admin/bot-health or /status."""
    out = {}
    for t in TELEGRAM_BOT_TOKENS:
        out[t[:12] + "..."] = {
            "available": _is_bot_available(t),
            "failures": _BOT_FAILURE_COUNT.get(t, 0),
            "circuit_open_until": _BOT_CIRCUIT_OPEN_UNTIL.get(t)
        }
    return out


_admin_bot_running = False


def send_telegram_message(chat_id: str, text: str):
    """Send a text message via the report/admin bot token."""
    token = TELEGRAM_ADMIN_BOT_TOKEN or (TELEGRAM_BOT_TOKENS[0] if TELEGRAM_BOT_TOKENS else "")
    if not token:
        raise ValueError("No Telegram bot tokens configured")
    url = f"{TELEGRAM_API_URL}/bot{token}/sendMessage"
    payload = {"chat_id": chat_id, "text": text, "parse_mode": "HTML"}
    response = requests.post(url, json=payload, timeout=10)
    response.raise_for_status()
    return response.json()


def send_user_notification(chat_id: str, text: str):
    """Send a notification to a user via the dedicated report bot (no channel needed)."""
    token = TELEGRAM_REPORT_BOT_TOKEN or TELEGRAM_ADMIN_BOT_TOKEN
    if not token:
        print("[TELEGRAM] No report bot token configured")
        return None
    if not chat_id:
        print("[TELEGRAM] No chat_id provided")
        return None
    url = f"{TELEGRAM_API_URL}/bot{token}/sendMessage"
    payload = {"chat_id": chat_id, "text": text, "parse_mode": "HTML"}
    try:
        response = requests.post(url, json=payload, timeout=10)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(f"[TELEGRAM] Failed to send notification: {e}")
        return None


def send_telegram_photo_with_buttons(chat_id: str, photo_file_id: str, caption: str, buttons: list):
    """Send a photo with inline keyboard buttons via the admin bot."""
    token = TELEGRAM_ADMIN_BOT_TOKEN or (TELEGRAM_BOT_TOKENS[0] if TELEGRAM_BOT_TOKENS else "")
    if not token:
        raise ValueError("No Telegram bot tokens configured")

    url = f"{TELEGRAM_API_URL}/bot{token}/sendPhoto"
    payload = {
        "chat_id": chat_id,
        "photo": photo_file_id,
        "caption": caption,
        "parse_mode": "HTML"
    }

    inline_keyboard = []
    for row in buttons:
        inline_keyboard.append([
            {"text": btn["text"], "callback_data": btn["callback"]}
            for btn in row
        ])
    payload["reply_markup"] = {"inline_keyboard": inline_keyboard}

    response = requests.post(url, json=payload, timeout=15)
    response.raise_for_status()
    return response.json()


def answer_callback_query(callback_query_id: str, text: str = ""):
    """Stop Telegram's inline-button loading state."""
    token = TELEGRAM_ADMIN_BOT_TOKEN or (TELEGRAM_BOT_TOKENS[0] if TELEGRAM_BOT_TOKENS else "")
    if not token or not callback_query_id:
        return
    response = requests.post(
        f"{TELEGRAM_API_URL}/bot{token}/answerCallbackQuery",
        json={"callback_query_id": callback_query_id, "text": text[:200]},
        timeout=10,
    )
    response.raise_for_status()


def edit_admin_report_message(chat_id: str, message_id: int, original_text: str, result: str, is_photo: bool = False):
    """Replace report buttons with a durable moderation result."""
    token = TELEGRAM_ADMIN_BOT_TOKEN or (TELEGRAM_BOT_TOKENS[0] if TELEGRAM_BOT_TOKENS else "")
    if not token or not chat_id or not message_id:
        return
    method = "editMessageCaption" if is_photo else "editMessageText"
    content_field = "caption" if is_photo else "text"
    response = requests.post(
        f"{TELEGRAM_API_URL}/bot{token}/{method}",
        json={
            "chat_id": chat_id,
            "message_id": message_id,
            content_field: f"{original_text}\n\n<b>Moderation result:</b> {result}",
            "parse_mode": "HTML",
            "reply_markup": {"inline_keyboard": []},
        },
        timeout=10,
    )
    response.raise_for_status()


def _handle_admin_command(update: dict, db_factory):
    from models import User, Challenge, ChallengeReport, UserBan

    message = update.get("message") or update.get("channel_post") or {}
    text = message.get("text", "")
    chat_id = str(message.get("chat", {}).get("id", ""))

    callback_query = update.get("callback_query")
    if callback_query:
        data = callback_query.get("data", "")
        callback_chat_id = str(callback_query.get("message", {}).get("chat", {}).get("id", ""))
        if TELEGRAM_ADMIN_CHAT_ID and callback_chat_id == str(TELEGRAM_ADMIN_CHAT_ID):
            try:
                result = _handle_admin_callback(data, db_factory, callback_query.get("message") or {})
                answer_callback_query(callback_query.get("id", ""), result or "Action completed")
            except Exception as e:
                print(f"Admin callback error: {e}")
                try:
                    answer_callback_query(callback_query.get("id", ""), "Action failed")
                except Exception as callback_error:
                    print(f"Admin callback acknowledgement failed: {callback_error}")
        return

    if not TELEGRAM_ADMIN_CHAT_ID or chat_id != str(TELEGRAM_ADMIN_CHAT_ID):
        return

    db = db_factory()
    try:
        if text.startswith("/reports"):
            reports = db.query(ChallengeReport).filter(ChallengeReport.status == "open").order_by(ChallengeReport.created_at.desc()).limit(10).all()
            if not reports:
                send_telegram_message(TELEGRAM_ADMIN_CHAT_ID, "✅ No open reports.")
                return

            lines = ["📋 <b>Open Reports:</b>\n"]
            for report in reports:
                challenge = db.query(Challenge).filter(Challenge.id == report.challenge_id).first()
                reporter = db.query(User).filter(User.id == report.reporter_id).first()
                title = challenge.title if challenge else "Unknown"
                reporter_name = reporter.username if reporter else "unknown"
                lines.append(f"#{report.id} - {title} (by {reporter_name})\nReason: {report.reason}")

            send_telegram_message(TELEGRAM_ADMIN_CHAT_ID, "\n".join(lines))

        elif text.startswith("/approve "):
            _resolve_command_report(db, text, "approve")

        elif text.startswith("/reject "):
            _resolve_command_report(db, text, "reject")

        elif text.startswith("/ban "):
            _resolve_command_report(db, text, "ban")

        elif text == "/status":
            from models import User as _User, Challenge as _Challenge, ChallengeReport as _Report
            from telegram_proxy import get_bot_health
            user_count = db.query(_User).count()
            challenge_count = db.query(_Challenge).count()
            community_count = db.query(_Challenge).filter(_Challenge.is_community == True).count()
            open_reports = db.query(_Report).filter(_Report.status == "open").count()
            telegram_users = db.query(_User).filter(_User.telegram_chat_id.isnot(None)).count()
            bots_configured = sum(1 for t in TELEGRAM_BOT_TOKENS if t)
            health = get_bot_health()
            health_lines = []
            for short_token, status in health.items():
                marker = "✅" if status["available"] else "❌"
                failures = status["failures"]
                health_lines.append(f"  {marker} <code>{short_token}</code> failures: {failures}")
            health_block = "\n".join(health_lines) if health_lines else "  None"
            try:
                from main import COMMUNITY_CTF_WEEKLY_LIMIT, COMMUNITY_CTF_EXPIRY_DAYS
                quota_text = f"📝 Quota: <b>{COMMUNITY_CTF_WEEKLY_LIMIT}/week</b>, expires after <b>{COMMUNITY_CTF_EXPIRY_DAYS} days</b>"
            except Exception:
                quota_text = ""
            status_text = (
                "📊 <b>CipherPoint Status</b>\n\n"
                f"👥 Total users: <b>{user_count}</b>\n"
                f"📡 Telegram-linked users: <b>{telegram_users}</b>\n"
                f"🎯 Total challenges: <b>{challenge_count}</b>\n"
                f"🧩 Community CTFs: <b>{community_count}</b>\n"
                f"🚨 Open reports: <b>{open_reports}</b>\n"
                f"🤖 Upload bots configured: <b>{bots_configured}</b>\n"
                f"🛡  Admin chat: <b>{TELEGRAM_ADMIN_CHAT_ID or 'NOT set'}</b>\n"
                f"📺 Channel ID: <b>{TELEGRAM_CHANNEL_ID or 'NOT set'}</b>\n"
                f"{quota_text}\n\n"
                f"<b>Bot Health</b>\n{health_block}"
            )
            send_telegram_message(TELEGRAM_ADMIN_CHAT_ID, status_text)

        elif text == "/stats":
            from models import User as _User, Challenge as _Challenge, ChallengeReport as _Report, SolvedChallenge as _Solved, Comment as _Comment
            user_count = db.query(_User).count()
            admin_count = db.query(_User).filter(_User.is_admin == True).count()
            telegram_users = db.query(_User).filter(_User.telegram_chat_id.isnot(None)).count()
            challenge_count = db.query(_Challenge).count()
            community_count = db.query(_Challenge).filter(_Challenge.is_community == True).count()
            solved_count = db.query(_Solved).count()
            comment_count = db.query(_Comment).count()
            open_reports = db.query(_Report).filter(_Report.status == "open").count()
            resolved_reports = db.query(_Report).filter(_Report.status == "resolved").count()
            top_user = db.query(_User).order_by(_User.rank_points.desc()).first()
            top_text = f"{top_user.username} ({top_user.rank_points} pts)" if top_user else "N/A"
            stats_text = (
                "📈 <b>CipherPoint Statistics</b>\n\n"
                f"<b>Users</b>\n"
                f"  Total: {user_count}\n"
                f"  Admins: {admin_count}\n"
                f"  Telegram-linked: {telegram_users}\n\n"
                f"<b>Challenges</b>\n"
                f"  Total: {challenge_count}\n"
                f"  Community: {community_count}\n"
                f"  Total solves: {solved_count}\n\n"
                f"<b>Engagement</b>\n"
                f"  Comments: {comment_count}\n\n"
                f"<b>Moderation</b>\n"
                f"  Open reports: {open_reports}\n"
                f"  Resolved reports: {resolved_reports}\n\n"
                f"🏆 Top analyst: <b>{top_text}</b>"
            )
            send_telegram_message(TELEGRAM_ADMIN_CHAT_ID, stats_text)

        elif text.startswith("/broadcast"):
            msg = text.replace("/broadcast", "", 1).strip()
            if not msg:
                send_telegram_message(TELEGRAM_ADMIN_CHAT_ID, "❌ Usage: <code>/broadcast &lt;your message&gt;</code>")
                return
            from models import User as _User
            recipients = db.query(_User).filter(
                _User.telegram_chat_id.isnot(None),
                _User.telegram_notifications == True
            ).all()
            sent = 0
            failed = 0
            for user in recipients:
                try:
                    personalized = f"📢 <b>CipherPoint Announcement</b>\n\n{escape_html(msg)}\n\n— CipherPoint Admin"
                    send_user_notification(user.telegram_chat_id, personalized)
                    sent += 1
                except Exception as e:
                    print(f"[BROADCAST] Failed for {user.username}: {e}")
                    failed += 1
            send_telegram_message(
                TELEGRAM_ADMIN_CHAT_ID,
                f"📢 <b>Broadcast complete</b>\n\n✅ Sent: {sent}\n❌ Failed: {failed}\n📝 Message length: {len(msg)} chars"
            )

        elif text == "/help":
            send_telegram_message(TELEGRAM_ADMIN_CHAT_ID,
                "🛡 <b>CipherPoint Admin Commands</b>\n\n"
                "<b>Moderation</b>\n"
                "/reports - List open challenge reports\n"
                "/approve <code>&lt;id&gt;</code> - Approve report (no action)\n"
                "/reject <code>&lt;id&gt;</code> - Reject report (hide challenge)\n"
                "/ban <code>&lt;id&gt;</code> - Reject + ban the reporter\n\n"
                "<b>Insights</b>\n"
                "/status - Quick platform health snapshot\n"
                "/stats - Detailed user & content statistics\n\n"
                "<b>Broadcast</b>\n"
                "/broadcast <code>&lt;message&gt;</code> - Send announcement to all Telegram-linked users\n\n"
                "💡 Tip: You can also tap the buttons on the report messages.")
    finally:
        db.close()


def _parse_report_id(command: str) -> int:
    parts = command.split()
    if len(parts) != 2:
        raise ValueError("Usage: /approve <id> (for example, /approve 3)")
    report_id = parts[1].lstrip("#")
    if not report_id.isdigit() or int(report_id) <= 0:
        raise ValueError("Report ID must be a positive number, for example 3 or #3")
    return int(report_id)


def _resolve_command_report(db: Session, command: str, action: str):
    try:
        report_id = _parse_report_id(command)
    except ValueError as error:
        send_telegram_message(TELEGRAM_ADMIN_CHAT_ID, f"❌ {error}")
        return
    result = _resolve_report(db, report_id, action, notify=False)
    send_telegram_message(TELEGRAM_ADMIN_CHAT_ID, result or "✅ Action completed.")


def _handle_admin_callback(data: str, db_factory, callback_message: dict):
    """Handle inline keyboard button clicks."""
    parts = data.split("_", 1)
    action = parts[0].strip().lower()
    try:
        report_id = int(parts[1]) if len(parts) > 1 else 0
    except (TypeError, ValueError):
        report_id = 0

    db = db_factory()
    try:
        message = _resolve_report(db, report_id, action, notify=False)
    finally:
        db.close()
    try:
        original_text = callback_message.get("text") or callback_message.get("caption") or "CipherPoint moderation report"
        edit_admin_report_message(
            str(callback_message.get("chat", {}).get("id", "")),
            int(callback_message.get("message_id") or 0),
            original_text,
            message or "Action completed",
            bool(callback_message.get("caption")),
        )
    except Exception as error:
        print(f"Admin report message update failed: {error}")
    return message


def _resolve_report(db: Session, report_id: int, action: str, notify: bool = True):
    """Resolve a report with the given action."""
    from models import ChallengeReport, Challenge, Comment, User, UserBan

    if action not in {"approve", "reject", "ban"}:
        return "❌ Invalid moderation action."

    report = db.query(ChallengeReport).filter(ChallengeReport.id == report_id).first()
    if not report:
        return "❌ Report not found."

    challenge = db.query(Challenge).filter(Challenge.id == report.challenge_id).first()
    comment = db.query(Comment).filter(Comment.id == report.comment_id).first() if report.comment_id else None
    admin = db.query(User).filter(User.is_admin == True).order_by(User.id.asc()).first()
    if not admin:
        return "❌ No admin account available to record this action."

    if action == "approve":
        report.status = "resolved"
        report.resolved_at = datetime.utcnow()
        report.resolved_by = admin.id
        db.commit()
        message = f"✅ Report #{report_id} approved."

    elif action == "reject":
        if challenge and report.comment_id is None:
            challenge.status = "removed"
        report.status = "resolved"
        report.resolved_at = datetime.utcnow()
        report.resolved_by = admin.id
        db.commit()
        target = "comment" if report.comment_id else "challenge"
        message = f"🗑️ Report #{report_id} rejected. {target.capitalize()} hidden."

    elif action == "ban":
        if challenge and report.comment_id is None:
            challenge.status = "removed"
        target_user_id = comment.user_id if comment else (challenge.created_by if challenge else None)
        existing_ban = db.query(UserBan).filter(UserBan.user_id == target_user_id).first() if target_user_id else None
        if not existing_ban:
            if not target_user_id:
                return "❌ Report target user not found."
            db.add(UserBan(user_id=target_user_id, reason="Report violation", banned_by=admin.id))
        report.status = "resolved"
        report.resolved_at = datetime.utcnow()
        report.resolved_by = admin.id
        db.commit()
        message = f"🚫 Report #{report_id} resolved with ban."

    try:
        from main import _cache_clear_prefix
        _cache_clear_prefix("challenges:")
    except ImportError:
        pass
    if notify:
        send_telegram_message(TELEGRAM_ADMIN_CHAT_ID, message)
    return message


def start_admin_bot_polling(db_factory):
    global _admin_bot_running
    if _admin_bot_running:
        return
    _admin_bot_running = True

    def poll():
        user_bot_offset = 0
        admin_bot_offset = 0
        while _admin_bot_running:
            try:
                if TELEGRAM_REPORT_BOT_TOKEN:
                    try:
                        url = f"{TELEGRAM_API_URL}/bot{TELEGRAM_REPORT_BOT_TOKEN}/getUpdates"
                        response = requests.get(
                            url,
                            params={"timeout": 5, "offset": user_bot_offset},
                            json=None,
                            timeout=10,
                        )
                        data = response.json()
                        if data.get("ok"):
                            for update in data.get("result", []):
                                user_bot_offset = max(user_bot_offset, update.get("update_id", 0) + 1)
                                _handle_user_bot_message(update, db_factory)
                    except Exception as e:
                        print(f"User bot polling error: {e}")

                if not TELEGRAM_ADMIN_BOT_TOKEN or not TELEGRAM_ADMIN_CHAT_ID:
                    _time.sleep(5)
                    continue

                url = f"{TELEGRAM_API_URL}/bot{TELEGRAM_ADMIN_BOT_TOKEN}/getUpdates"
                # Telegram API expects allowed_updates as a JSON array string,
                # not a Python list (which would create duplicate query params).
                allowed_updates_json = json.dumps(["message", "callback_query"])
                response = requests.get(
                    url,
                    params={"timeout": 30, "offset": admin_bot_offset, "allowed_updates": allowed_updates_json},
                    timeout=35,
                )
                response.raise_for_status()
                data = response.json()

                if data.get("ok"):
                    for update in data.get("result", []):
                        admin_bot_offset = max(admin_bot_offset, update.get("update_id", 0) + 1)
                        _handle_admin_command(update, db_factory)
            except requests.exceptions.HTTPError as e:
                # 409 = another instance is polling. Back off longer.
                if e.response is not None and e.response.status_code == 409:
                    print(f"Admin bot 409 Conflict: another instance is polling. Backing off 60s.")
                    _time.sleep(60)
                else:
                    print(f"Admin bot polling error: {e}")
                    _time.sleep(5)
            except Exception as e:
                print(f"Admin bot polling error: {e}")
                # Random jitter to avoid thundering herd if multiple instances exist
                import random
                _time.sleep(5 + random.uniform(0, 5))

    thread = threading.Thread(target=poll, daemon=True)
    thread.start()


def _handle_user_bot_message(update, db_factory):
    try:
        message = update.get("message") or {}
        chat = message.get("chat") or {}
        text = (message.get("text") or "").strip()
        chat_id = str(chat.get("id"))
        if not chat_id:
            return

        db = db_factory()
        try:
            from models import User
            from datetime import datetime

            user = db.query(User).filter(User.telegram_chat_id == chat_id).first()

            if text.startswith("/start"):
                payload = text.replace("/start", "", 1).strip()

                if payload.startswith("connect_"):
                    parts = payload.split("_", 2)
                    if len(parts) >= 3:
                        user_id_part = parts[1]
                        nonce_part = parts[2]
                        if user_id_part.isdigit():
                            candidate = db.query(User).filter(User.id == int(user_id_part)).first()
                            if candidate:
                                stored_nonce = getattr(candidate, "telegram_connect_nonce", None)
                                expires = getattr(candidate, "telegram_connect_nonce_expires", None)
                                if (
                                    stored_nonce
                                    and nonce_part == stored_nonce
                                    and expires
                                    and expires > datetime.utcnow()
                                ):
                                    user = candidate
                                else:
                                    send_user_notification(
                                        chat_id,
                                        "❌ <b>Connection failed</b>\n\n"
                                        "This link is invalid or has expired. Please open the "
                                        "Settings page in the app and click 'Connect Telegram' again to "
                                        "generate a fresh link."
                                    )
                                    return
                    else:
                        if not user:
                            send_user_notification(
                                chat_id,
                                "👋 <b>Welcome to CipherPoint!</b>\n\n"
                                "Please open the Settings page in the app and click 'Connect Telegram' to link your account."
                            )
                            return

                if not user:
                    send_user_notification(
                        chat_id,
                        "👋 <b>Welcome to CipherPoint!</b>\n\n"
                        "Please open the Settings page in the app and click 'Connect Telegram' to link your account."
                    )
                    return

                user.telegram_chat_id = chat_id
                if not user.telegram_notifications:
                    user.telegram_notifications = True
                user.telegram_connect_nonce = None
                user.telegram_connect_nonce_expires = None
                db.commit()

                username = user.username or "analyst"
                send_user_notification(
                    chat_id,
                    f"✅ <b>CipherPoint connected</b>\n\n"
                    f"Hello <b>{username}</b>! Your Telegram is now linked to your CipherPoint account.\n\n"
                    f"You will receive notifications for:\n"
                    f"• New case releases\n"
                    f"• Replies to your comments\n"
                    f"• Achievement unlocks\n"
                    f"• Password reset requests\n\n"
                    f"Manage preferences in Settings → Notifications."
                )

            elif text == "/help":
                send_user_notification(
                    chat_id,
                    "🤖 <b>CipherPoint Bot Commands</b>\n\n"
                    "/start - Link or activate your account\n"
                    "/connect - Get instructions to link your account\n"
                    "/status - Check your Telegram link status\n"
                    "/unlink - Remove Telegram link from your account\n"
                    "/help - Show this help message\n\n"
                    "🔐 Login OTPs are sent here when you use the 'Login with Telegram OTP' option on the website."
                )

            elif text == "/connect":
                send_user_notification(
                    chat_id,
                    "🔗 <b>Connect Your CipherPoint Account</b>\n\n"
                    "1. Open CipherPoint in your browser\n"
                    "2. Sign in with your username & password\n"
                    "3. Go to <b>Settings → Telegram Notifications</b>\n"
                    "4. Click <b>Connect Telegram</b>\n"
                    "5. This bot will open and automatically link your account\n\n"
                    "After linking, you can:\n"
                    "• Login with Telegram OTP (no password needed)\n"
                    "• Receive password reset codes\n"
                    "• Get case notifications & replies"
                )

            elif text == "/status":
                if not user:
                    send_user_notification(
                        chat_id,
                        "❌ <b>Not linked</b>\n\n"
                        "This Telegram account is not connected to any CipherPoint user.\n"
                        "Send /connect to see how to link."
                    )
                else:
                    notif_state = "ON ✅" if user.telegram_notifications else "OFF ❌"
                    send_user_notification(
                        chat_id,
                        "📊 <b>Link Status</b>\n\n"
                        f"Username: <b>{escape_html(user.username)}</b>\n"
                        f"Telegram linked: <b>Yes ✅</b>\n"
                        f"Chat ID: <code>{chat_id}</code>\n"
                        f"Notifications: <b>{notif_state}</b>\n"
                        f"Coins: <b>{user.coins}</b>\n"
                        f"Rank points: <b>{user.rank_points}</b>\n\n"
                        f"Send /unlink to disconnect."
                    )

            elif text == "/unlink":
                if not user:
                    send_user_notification(
                        chat_id,
                        "ℹ️ This Telegram account is not linked to any CipherPoint profile."
                    )
                    return
                user.telegram_chat_id = None
                user.telegram_notifications = False
                user.telegram_connect_nonce = None
                user.telegram_connect_nonce_expires = None
                user.login_otp_code = None
                user.login_otp_expires = None
                user.login_otp_attempts = 0
                db.commit()
                send_user_notification(
                    chat_id,
                    "✅ <b>Telegram unlinked</b>\n\n"
                    "Your CipherPoint account is no longer connected to this Telegram.\n"
                    "You will not receive OTPs, password resets, or case notifications here.\n\n"
                    "To reconnect later, open Settings → Connect Telegram."
                )

            else:
                if not user:
                    send_user_notification(
                        chat_id,
                        "👋 <b>CipherPoint Bot</b>\n\n"
                        "Your Telegram is not linked yet. Send /connect to see how to link your account.\n"
                        "Send /help anytime for available commands."
                    )
        finally:
            db.close()
    except Exception as e:
        print(f"User bot message handler error: {e}")


def get_telegram_file(file_id: str):
    """Fetch file from Telegram private channel using the configured bot tokens."""
    try:
        tokens = _get_bot_tokens()
        if not tokens:
            raise ValueError("No Telegram bot tokens configured")

        last_error = None
        for bot_token in tokens:
            try:
                get_file_url = f"{TELEGRAM_API_URL}/bot{bot_token}/getFile"
                params = {"file_id": file_id}

                response = requests.get(get_file_url, params=params, timeout=10)
                response.raise_for_status()

                file_info = response.json()
                if not file_info.get("ok"):
                    continue

                file_path = file_info["result"]["file_path"]
                download_url = f"{TELEGRAM_API_URL}/file/bot{bot_token}/{file_path}"

                file_response = requests.get(download_url, stream=True, timeout=30)
                file_response.raise_for_status()

                mime_type = "application/octet-stream"
                if file_path.lower().endswith(('.jpg', '.jpeg')):
                    mime_type = "image/jpeg"
                elif file_path.lower().endswith('.png'):
                    mime_type = "image/png"
                elif file_path.lower().endswith('.gif'):
                    mime_type = "image/gif"
                elif file_path.lower().endswith(('.mp4', '.webm', '.mov')):
                    mime_type = "video/mp4"
                elif file_path.lower().endswith('.pdf'):
                    mime_type = "application/pdf"

                return StreamingResponse(
                    file_response.iter_content(chunk_size=8192),
                    media_type=mime_type,
                    headers={
                        "Cache-Control": "public, max-age=86400",
                        "Content-Disposition": f"inline; filename={file_path.split('/')[-1]}"
                    }
                )
            except Exception as e:
                last_error = e
                continue

        raise Exception(f"Failed to retrieve file from any bot: {str(last_error)}")

    except Exception as e:
        raise Exception(f"Error fetching media: {str(e)}")


def validate_media_duration(file_path: str, mime_type: str = "") -> None:
    """Reject videos longer than 10 seconds when ffprobe is available."""
    if not mime_type.startswith("video/"):
        return

    if not os.path.exists(file_path):
        return

    try:
        result = subprocess.run([
            "ffprobe",
            "-v",
            "error",
            "-show_entries",
            "format=duration",
            "-of",
            "default=noprint_wrappers=1:nokey=1",
            file_path,
        ], capture_output=True, text=True, timeout=15)
        if result.returncode != 0:
            return

        duration = float((result.stdout or "0").strip() or 0)
        if duration > 10:
            raise ValueError("Video duration must be 10 seconds or less.")
    except (FileNotFoundError, ValueError, TypeError):
        if mime_type.startswith("video/"):
            return


def upload_to_telegram(file_path: str, chat_id: str = None, bot_token: str = None):
    """Upload a file to Telegram using either a specific bot or round-robin selection."""
    if not chat_id:
        chat_id = TELEGRAM_CHANNEL_ID
    if not chat_id:
        raise ValueError("No Telegram channel ID configured")

    file_ext = os.path.splitext(file_path)[1].lower()
    media_kind = "application/octet-stream"
    if file_ext in {".png", ".jpg", ".jpeg", ".gif", ".webp"}:
        media_kind = "image"
    elif file_ext in {".mp4", ".mov", ".webm"}:
        media_kind = "video"

    candidates = [bot_token] if bot_token else _get_bot_tokens()
    last_error = None
    attempted_bots = set()

    for attempt_bot in candidates:
        if attempt_bot in attempted_bots:
            continue
        attempted_bots.add(attempt_bot)

        if not _is_bot_available(attempt_bot):
            print(f"[UPLOAD] Skipping bot {attempt_bot[:10]}... (circuit open)")
            continue

        with _BOT_LOCKS[attempt_bot]:
            try:
                with open(file_path, 'rb') as file:
                    if media_kind == "image":
                        url = f"{TELEGRAM_API_URL}/bot{attempt_bot}/sendPhoto"
                        files = {'photo': file}
                    elif media_kind == "video":
                        url = f"{TELEGRAM_API_URL}/bot{attempt_bot}/sendVideo"
                        files = {'video': file}
                    else:
                        url = f"{TELEGRAM_API_URL}/bot{attempt_bot}/sendDocument"
                        files = {'document': file}
                    payload = {'chat_id': chat_id}

                    response = requests.post(url, files=files, data=payload, timeout=60)

                    if response.status_code == 429:
                        retry_after = int(response.json().get("parameters", {}).get("retry_after", 5))
                        print(f"[UPLOAD] Rate limited, sleeping {retry_after}s")
                        _time.sleep(min(retry_after, 30))
                        response = requests.post(url, files=files, data=payload, timeout=60)

                    response.raise_for_status()
                    result = response.json()

                    if not result.get("ok"):
                        raise Exception(result.get("description") or "Failed to upload to Telegram")

                    if media_kind == "image":
                        file_id = result["result"]["photo"][-1]["file_id"]
                    elif media_kind == "video":
                        file_id = result["result"]["video"]["file_id"]
                    else:
                        file_id = result["result"]["document"]["file_id"]

                    _mark_bot_success(attempt_bot)
                    return file_id, attempt_bot
            except Exception as e:
                last_error = e
                _mark_bot_failure(attempt_bot)
                print(f"[UPLOAD] Bot {attempt_bot[:10]}... failed: {e}")
                continue

    raise Exception(f"All upload bots failed. Last error: {str(last_error)}")


def upload_media_to_channel(file_path: str, mime_type: str = "application/octet-stream", chat_id: str = None):
    """Upload a file to Telegram channel using round-robin bot selection with retry."""
    if not file_path or not os.path.exists(file_path):
        raise ValueError("File does not exist")

    validate_media_duration(file_path, mime_type)

    selected_channel = chat_id or TELEGRAM_CHANNEL_ID

    file_id, bot_token = upload_to_telegram(file_path=file_path, chat_id=selected_channel)
    return {
        "file_id": file_id,
        "bot_token": bot_token[:12] + "..." if bot_token else None,
        "channel_id": selected_channel,
    }
