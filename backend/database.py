from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.ext.declarative import declarative_base
import os
from dotenv import load_dotenv

load_dotenv()

from turso_client import is_turso_configured, connect_turso


def _make_engine():
    """Build the SQLAlchemy engine against the configured Turso database."""
    if not is_turso_configured():
        raise RuntimeError("TURSO_URL and TURSO_AUTH_TOKEN must be configured")

    from sqlalchemy.pool import StaticPool
    creator = lambda: connect_turso(
        os.getenv("TURSO_URL", "").strip(),
        os.getenv("TURSO_AUTH_TOKEN", "").strip(),
    )
    return create_engine(
        "sqlite:///:memory:",
        creator=creator,
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
        echo=False
    )


engine = _make_engine()
IS_TURSO = True
IS_POSTGRES = False

# Create session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class for all models
Base = declarative_base()

# Dependency for FastAPI to get database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Create all tables
def init_db():
    Base.metadata.create_all(bind=engine)
    if IS_POSTGRES:
        return  # PostgreSQL migrations require Alembic in production
    with engine.begin() as conn:
        user_columns = conn.execute(text("PRAGMA table_info(users)")).fetchall()
        if not any(column[1] == "is_admin" for column in user_columns):
            conn.execute(text("ALTER TABLE users ADD COLUMN is_admin BOOLEAN DEFAULT 0 NOT NULL"))
        if not any(column[1] == "bio" for column in user_columns):
            conn.execute(text("ALTER TABLE users ADD COLUMN bio TEXT"))
        if not any(column[1] == "avatar_url" for column in user_columns):
            conn.execute(text("ALTER TABLE users ADD COLUMN avatar_url VARCHAR"))
        if not any(column[1] == "notify_new_challenges" for column in user_columns):
            conn.execute(text("ALTER TABLE users ADD COLUMN notify_new_challenges BOOLEAN DEFAULT 1 NOT NULL"))
        if not any(column[1] == "notify_comments" for column in user_columns):
            conn.execute(text("ALTER TABLE users ADD COLUMN notify_comments BOOLEAN DEFAULT 1 NOT NULL"))
        if not any(column[1] == "notify_mentions" for column in user_columns):
            conn.execute(text("ALTER TABLE users ADD COLUMN notify_mentions BOOLEAN DEFAULT 1 NOT NULL"))
        if not any(column[1] == "hide_email" for column in user_columns):
            conn.execute(text("ALTER TABLE users ADD COLUMN hide_email BOOLEAN DEFAULT 1 NOT NULL"))
        if not any(column[1] == "public_profile" for column in user_columns):
            conn.execute(text("ALTER TABLE users ADD COLUMN public_profile BOOLEAN DEFAULT 1 NOT NULL"))
        if not any(column[1] == "telegram_chat_id" for column in user_columns):
            conn.execute(text("ALTER TABLE users ADD COLUMN telegram_chat_id VARCHAR"))
        if not any(column[1] == "telegram_notifications" for column in user_columns):
            conn.execute(text("ALTER TABLE users ADD COLUMN telegram_notifications BOOLEAN DEFAULT 1 NOT NULL"))
        if not any(column[1] == "telegram_connect_nonce" for column in user_columns):
            conn.execute(text("ALTER TABLE users ADD COLUMN telegram_connect_nonce VARCHAR"))
        if not any(column[1] == "telegram_connect_nonce_expires" for column in user_columns):
            conn.execute(text("ALTER TABLE users ADD COLUMN telegram_connect_nonce_expires DATETIME"))
        if not any(column[1] == "reset_token" for column in user_columns):
            conn.execute(text("ALTER TABLE users ADD COLUMN reset_token VARCHAR"))
        if not any(column[1] == "reset_token_expires" for column in user_columns):
            conn.execute(text("ALTER TABLE users ADD COLUMN reset_token_expires DATETIME"))
        if not any(column[1] == "login_otp_code" for column in user_columns):
            conn.execute(text("ALTER TABLE users ADD COLUMN login_otp_code VARCHAR"))
        if not any(column[1] == "login_otp_expires" for column in user_columns):
            conn.execute(text("ALTER TABLE users ADD COLUMN login_otp_expires DATETIME"))
        if not any(column[1] == "login_otp_attempts" for column in user_columns):
            conn.execute(text("ALTER TABLE users ADD COLUMN login_otp_attempts INTEGER DEFAULT 0 NOT NULL"))
        if not any(column[1] == "login_otp_username" for column in user_columns):
            conn.execute(text("ALTER TABLE users ADD COLUMN login_otp_username VARCHAR"))
        if not any(column[1] == "login_otp_requested_at" for column in user_columns):
            conn.execute(text("ALTER TABLE users ADD COLUMN login_otp_requested_at DATETIME"))
        if not any(column[1] == "daily_bonus_claimed_at" for column in user_columns):
            conn.execute(text("ALTER TABLE users ADD COLUMN daily_bonus_claimed_at DATETIME"))
        if not any(column[1] == "weekly_challenges_used" for column in user_columns):
            conn.execute(text("ALTER TABLE users ADD COLUMN weekly_challenges_used INTEGER DEFAULT 0 NOT NULL"))
        if not any(column[1] == "weekly_reset_at" for column in user_columns):
            conn.execute(text("ALTER TABLE users ADD COLUMN weekly_reset_at DATETIME"))
        if not any(column[1] == "failed_login_count" for column in user_columns):
            conn.execute(text("ALTER TABLE users ADD COLUMN failed_login_count INTEGER DEFAULT 0 NOT NULL"))
        if not any(column[1] == "locked_until" for column in user_columns):
            conn.execute(text("ALTER TABLE users ADD COLUMN locked_until DATETIME"))
        if not any(column[1] == "last_failed_login_at" for column in user_columns):
            conn.execute(text("ALTER TABLE users ADD COLUMN last_failed_login_at DATETIME"))

        challenge_columns = conn.execute(text("PRAGMA table_info(challenges)")).fetchall()
        for column_name, default_sql in [
            ("created_by", "INTEGER"),
            ("status", "VARCHAR DEFAULT 'approved' NOT NULL"),
            ("is_community", "BOOLEAN DEFAULT 0 NOT NULL"),
            ("disclaimer_accepted", "BOOLEAN DEFAULT 0 NOT NULL"),
            ("tags", "VARCHAR DEFAULT ''"),
            ("report_count", "INTEGER DEFAULT 0 NOT NULL"),
            ("solution_walkthrough", "TEXT"),
        ]:
            if not any(column[1] == column_name for column in challenge_columns):
                conn.execute(text(f"ALTER TABLE challenges ADD COLUMN {column_name} {default_sql}"))

        comment_columns = conn.execute(text("PRAGMA table_info(comments)")).fetchall()
        if comment_columns and not any(column[1] == "parent_id" for column in comment_columns):
            conn.execute(text("ALTER TABLE comments ADD COLUMN parent_id INTEGER REFERENCES comments(id)"))

        report_columns = conn.execute(text("PRAGMA table_info(challenge_reports)")).fetchall()
        if report_columns and not any(column[1] == "comment_id" for column in report_columns):
            conn.execute(text("ALTER TABLE challenge_reports ADD COLUMN comment_id INTEGER REFERENCES comments(id)"))
        if report_columns and not any(column[1] == "target_type" for column in report_columns):
            conn.execute(text("ALTER TABLE challenge_reports ADD COLUMN target_type VARCHAR DEFAULT 'challenge' NOT NULL"))

        ban_columns = conn.execute(text("PRAGMA table_info(user_bans)")).fetchall()
        if ban_columns and not any(column[1] == "expires_at" for column in ban_columns):
            conn.execute(text("ALTER TABLE user_bans ADD COLUMN expires_at DATETIME"))

        conn.execute(text(
            "DELETE FROM unlocked_hints WHERE rowid NOT IN ("
            "SELECT MIN(rowid) FROM unlocked_hints GROUP BY user_id, challenge_id, hint_number)"
        ))
        conn.execute(text(
            "CREATE UNIQUE INDEX IF NOT EXISTS uq_unlocked_hints_user_challenge_number "
            "ON unlocked_hints (user_id, challenge_id, hint_number)"
        ))

        conn.execute(text(
            "CREATE UNIQUE INDEX IF NOT EXISTS uq_solved_challenge_user_challenge "
            "ON solved_challenges (user_id, challenge_id)"
        ))
