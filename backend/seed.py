"""
Seed script to populate CipherPoint database with sample OSINT challenges
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from database import SessionLocal, engine, Base
from models import User, Challenge, SolvedChallenge, UnlockedHint, ChallengeReport, UserBan
import bcrypt

def hash_password(password: str) -> str:
    """Hash password using bcrypt"""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def seed_database():
    """Populate database with sample data"""
    
    # Create tables
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    
    print("🌱 Starting database seeding...")
    
    # Clear existing data
    db.query(SolvedChallenge).delete()
    db.query(UnlockedHint).delete()
    db.query(ChallengeReport).delete()
    db.query(Challenge).delete()
    db.query(UserBan).delete()
    db.query(User).delete()
    db.commit()
    print("🧹 Cleared existing data")
    
    # Add sample users
    admin = User(
        username="admin",
        email="admin@cipherpoint.com",
        password_hash=hash_password("admin123"),
        is_admin=True,
        coins=1000,
        rank_points=5000
    )
    
    user1 = User(
        username="john_osint",
        email="john@example.com",
        password_hash=hash_password("password123"),
        coins=250,
        rank_points=1500
    )
    
    user2 = User(
        username="sarah_analyst",
        email="sarah@example.com",
        password_hash=hash_password("password456"),
        coins=180,
        rank_points=1200
    )
    
    db.add_all([admin, user1, user2])
    db.commit()
    print("✅ Users created: admin, john_osint, sarah_analyst")
    
    # Add sample challenges
    challenge1 = Challenge(
        title="Hidden Metadata: Identify the Location from GPS Data",
        category="GEOINT",
        difficulty="Easy",
        description="""
A suspect uploaded a photo on social media. Your task is to analyze the image metadata and identify the geographical location where the photo was taken. 

The photo has EXIF data embedded. Extract and analyze the GPS coordinates to pinpoint the location.

Tools you might need: ExifTool, Online EXIF viewers
Hints: Check EXIF data, focus on GPS tags, convert coordinates to map.
        """,
        telegram_file_id="AgACAgIAAxkBAAIBEGdabc123xyz",  # Dummy Telegram file ID
        correct_flag="40.7128,-74.0060",  # NYC coordinates
        points_reward=150,
        hint_1="Use an online EXIF viewer to extract metadata from the image. Look for GPS tags.",
        hint_1_cost=10,
        hint_2="The coordinates are in decimal format. Check if they correspond to a major city.",
        hint_2_cost=20
    )
    
    challenge2 = Challenge(
        title="Video Forensics: Find the Timestamp of Incident",
        category="Video Forensics",
        difficulty="Medium",
        description="""
A surveillance video shows a critical incident. Analyze the video metadata and frame-by-frame content to identify the exact timestamp when the incident occurred.

The video file contains metadata about its creation time. Also look for any visible clues in the video frames.

Watch carefully and report the time in HH:MM:SS format.
        """,
        telegram_file_id="BAACAgIAAxkBAAIBEGddef456uvw",  # Dummy Telegram file ID
        correct_flag="14:32:45",  # Specific timestamp
        points_reward=200,
        hint_1="Video metadata can be extracted using FFmpeg or MediaInfo. Check the creation date and time.",
        hint_1_cost=10,
        hint_2="Look at the clock visible in the video frames for additional confirmation.",
        hint_2_cost=20
    )
    
    challenge3 = Challenge(
        title="OSINT Investigation: Find Username from Social Media Trail",
        category="OSINT",
        difficulty="Hard",
        description="""
You've been provided with a single image and some text fragments. Using open-source intelligence techniques, trace the digital footprint and identify the real username of a person.

This challenge requires you to:
1. Analyze the image for hidden clues
2. Search for related information online
3. Cross-reference multiple data points
4. Identify the actual username

This is a real-world scenario. Use Google, reverse image search, social media platforms, and other OSINT tools.
        """,
        telegram_file_id="CAACAgIAAxkBAAIBEGdghi789klm",  # Dummy Telegram file ID
        correct_flag="@digitalshadow2023",  # Username
        points_reward=300,
        hint_1="Try reverse image search to find where this image appears online.",
        hint_1_cost=10,
        hint_2="The username is likely associated with one of the major social media platforms. Check Twitter, Reddit, Instagram.",
        hint_2_cost=20
    )
    
    db.add_all([challenge1, challenge2, challenge3])
    db.commit()
    print("✅ Challenges created:")
    print("   1. Hidden Metadata: Identify Location from GPS Data [Easy]")
    print("   2. Video Forensics: Find Timestamp [Medium]")
    print("   3. OSINT Investigation: Find Username [Hard]")
    
    db.close()
    print("\n✨ Database seeding completed successfully!")
    print("\nLogin credentials:")
    print("  Username: admin | Password: admin123")
    print("  Username: john_osint | Password: password123")
    print("  Username: sarah_analyst | Password: password456")

if __name__ == "__main__":
    seed_database()
