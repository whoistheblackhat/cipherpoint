from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, Float, Boolean, ForeignKey, UniqueConstraint
from sqlalchemy.orm import relationship
from database import Base

# Users Table
class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    is_admin = Column(Boolean, default=False, nullable=False)
    coins = Column(Integer, default=50)  # Default 50 coins on signup
    rank_points = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)
    bio = Column(Text, nullable=True)
    avatar_url = Column(String, nullable=True)
    notify_new_challenges = Column(Boolean, default=True, nullable=False)
    notify_comments = Column(Boolean, default=True, nullable=False)
    notify_mentions = Column(Boolean, default=True, nullable=False)
    hide_email = Column(Boolean, default=True, nullable=False)
    public_profile = Column(Boolean, default=True, nullable=False)
    telegram_chat_id = Column(String, nullable=True)
    telegram_notifications = Column(Boolean, default=True, nullable=False)
    telegram_connect_nonce = Column(String, nullable=True)
    telegram_connect_nonce_expires = Column(DateTime, nullable=True)
    reset_token = Column(String, nullable=True)
    reset_token_expires = Column(DateTime, nullable=True)
    login_otp_code = Column(String, nullable=True)
    login_otp_expires = Column(DateTime, nullable=True)
    login_otp_attempts = Column(Integer, default=0, nullable=False)
    login_otp_username = Column(String, nullable=True)
    login_otp_requested_at = Column(DateTime, nullable=True)
    daily_bonus_claimed_at = Column(DateTime, nullable=True)
    weekly_challenges_used = Column(Integer, default=0, nullable=False)
    weekly_reset_at = Column(DateTime, nullable=True)
    daily_streak = Column(Integer, default=0, nullable=False)
    reports_approved = Column(Integer, default=0, nullable=False)
    hints_unlocked = Column(Integer, default=0, nullable=False)
    profile_views = Column(Integer, default=0, nullable=False)
    fastest_solve_seconds = Column(Integer, nullable=True)
    first_solve_at = Column(DateTime, nullable=True)
    # Account lockout (defends against password brute-force)
    failed_login_count = Column(Integer, default=0, nullable=False)
    locked_until = Column(DateTime, nullable=True)
    last_failed_login_at = Column(DateTime, nullable=True)
    
    # Relationships
    solved_challenges = relationship("SolvedChallenge", back_populates="user")
    unlocked_hints = relationship("UnlockedHint", back_populates="user")
    reports = relationship("ChallengeReport", back_populates="reporter", foreign_keys="ChallengeReport.reporter_id")
    bans = relationship("UserBan", back_populates="user", foreign_keys="UserBan.user_id")


# Challenges Table
class Challenge(Base):
    __tablename__ = "challenges"
    
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, nullable=False)
    category = Column(String, nullable=False)  # e.g., "GEOINT", "Video Forensics", "Metadata"
    difficulty = Column(String, nullable=False)  # "Easy", "Medium", "Hard"
    description = Column(Text, nullable=False)
    telegram_file_id = Column(String, nullable=False)  # File ID from Telegram
    correct_flag = Column(String, nullable=False)  # The correct answer/flag
    points_reward = Column(Integer, default=100)  # Coins awarded for solving
    hint_1 = Column(Text, nullable=True)
    hint_1_cost = Column(Integer, default=10)  # Cost in coins
    hint_2 = Column(Text, nullable=True)
    hint_2_cost = Column(Integer, default=20)  # Cost in coins
    # Walkthrough shown to users after they solve the challenge. Empty
    # by default; admins / community authors can add a full step-by-step.
    solution_walkthrough = Column(Text, nullable=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    status = Column(String, default="approved", nullable=False)
    is_community = Column(Boolean, default=False, nullable=False)
    disclaimer_accepted = Column(Boolean, default=False, nullable=False)
    tags = Column(String, default="", nullable=True)
    report_count = Column(Integer, default=0, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    solved_by = relationship("SolvedChallenge", back_populates="challenge")
    unlocked_hints = relationship("UnlockedHint", back_populates="challenge")
    reports = relationship("ChallengeReport", back_populates="challenge")


# Solved Challenges Table (tracks which user solved which challenge)
class SolvedChallenge(Base):
    __tablename__ = "solved_challenges"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    challenge_id = Column(Integer, ForeignKey("challenges.id"), nullable=False)
    solved_at = Column(DateTime, default=datetime.utcnow)

    __table_args__ = (
        UniqueConstraint("user_id", "challenge_id", name="uq_solved_challenge_user_challenge"),
    )
    
    # Relationships
    user = relationship("User", back_populates="solved_challenges")
    challenge = relationship("Challenge", back_populates="solved_by")


# Unlocked Hints Table (tracks hint purchases)
class UnlockedHint(Base):
    __tablename__ = "unlocked_hints"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    challenge_id = Column(Integer, ForeignKey("challenges.id"), nullable=False)
    hint_number = Column(Integer, nullable=False)  # 1 or 2
    unlocked_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    user = relationship("User", back_populates="unlocked_hints")
    challenge = relationship("Challenge", back_populates="unlocked_hints")


class ChallengeReport(Base):
    __tablename__ = "challenge_reports"

    id = Column(Integer, primary_key=True, index=True)
    challenge_id = Column(Integer, ForeignKey("challenges.id"), nullable=False)
    comment_id = Column(Integer, ForeignKey("comments.id"), nullable=True)
    target_type = Column(String, default="challenge", nullable=False)
    reporter_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    reason = Column(String, nullable=False)
    details = Column(Text, default="")
    status = Column(String, default="open", nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    resolved_at = Column(DateTime, nullable=True)
    resolved_by = Column(Integer, ForeignKey("users.id"), nullable=True)

    challenge = relationship("Challenge", back_populates="reports")
    reporter = relationship("User", back_populates="reports", foreign_keys=[reporter_id])
    resolver = relationship("User", foreign_keys=[resolved_by])


class UserBan(Base):
    __tablename__ = "user_bans"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, unique=True)
    reason = Column(Text, nullable=False)
    banned_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)  # NULL = permanent ban

    user = relationship("User", back_populates="bans", foreign_keys=[user_id])
    banner = relationship("User", foreign_keys=[banned_by])

    @property
    def is_active(self) -> bool:
        """A ban is active if it has no expiry OR its expiry is in the future."""
        if self.expires_at is None:
            return True
        return self.expires_at > datetime.utcnow()


class Comment(Base):
    __tablename__ = "comments"

    id = Column(Integer, primary_key=True, index=True)
    challenge_id = Column(Integer, ForeignKey("challenges.id"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    body = Column(Text, nullable=False)
    parent_id = Column(Integer, ForeignKey("comments.id"), nullable=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    challenge = relationship("Challenge", backref="comments")
    author = relationship("User")
    parent = relationship("Comment", remote_side=[id], backref="replies")
