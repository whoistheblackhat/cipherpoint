#!/usr/bin/env python3
"""
Force-clean all Telegram bot state.
- Deletes any webhook
- Discards pending updates
- Useful for resolving 409 Conflict errors

Usage:
  python check_bots.py            # just check (safe)
  python check_bots.py --reset    # delete webhooks + clear pending updates
"""
import os
import re
import sys
import requests
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(__file__), "backend", ".env"))


def extract_tokens():
    tokens = {}
    for key, val in os.environ.items():
        if not val:
            continue
        if "TOKEN" not in key.upper() and "BOT" not in key.upper():
            continue
        found = re.findall(r"\d{6,12}:[A-Za-z0-9_-]{30,}", str(val))
        for t in found:
            tokens.setdefault(key, []).append(t)
    return tokens


def check_bot(token, label):
    print(f"\n{'='*70}")
    print(f"Bot: {label}")
    print(f"Token: {token[:10]}...{token[-5:]}")
    print("-" * 70)
    try:
        r = requests.get(f"https://api.telegram.org/bot{token}/getWebhookInfo", timeout=10)
        d = r.json()
        if d.get("ok"):
            wh = d["result"]
            print(f"  Webhook URL:     {wh.get('url') or '(not set)'}")
            print(f"  Pending updates: {wh.get('pending_update_count', 0)}")
            if wh.get("last_error_message"):
                print(f"  Last error:      {wh.get('last_error_message')}")
    except Exception as e:
        print(f"  ✗ Error: {e}")


def reset_bot(token, label):
    """Delete webhook + clear pending updates."""
    print(f"\n[RESET] {label} {token[:10]}...{token[-5:]}")

    # 1. Delete webhook (also clears pending updates if drop_pending_updates=True)
    try:
        r = requests.get(
            f"https://api.telegram.org/bot{token}/deleteWebhook",
            params={"drop_pending_updates": "true"},
            timeout=10,
        )
        d = r.json()
        if d.get("ok"):
            print(f"  ✓ Webhook deleted, pending updates dropped")
        else:
            print(f"  ✗ {d}")
    except Exception as e:
        print(f"  ✗ deleteWebhook failed: {e}")

    # 2. Confirm clean state
    try:
        r = requests.get(f"https://api.telegram.org/bot{token}/getWebhookInfo", timeout=10)
        d = r.json()
        if d.get("ok"):
            wh = d["result"]
            print(f"  Status: webhook='{wh.get('url') or '(none)'}' pending={wh.get('pending_update_count', 0)}")
    except Exception as e:
        print(f"  ✗ verify failed: {e}")


def main():
    do_reset = "--reset" in sys.argv
    tokens = extract_tokens()
    if not tokens:
        print("No bot tokens found in .env")
        sys.exit(1)

    total = sum(len(v) for v in tokens.values())
    print(f"Found {total} bot token(s) across {len(tokens)} env var(s)")

    if do_reset:
        print("\n⚠️  RESET MODE: Will delete all webhooks and drop pending updates")
        confirm = input("Type 'yes' to continue: ").strip().lower()
        if confirm != "yes":
            print("Aborted.")
            sys.exit(0)
        for key, toks in tokens.items():
            for i, t in enumerate(toks, 1):
                label = key if len(toks) == 1 else f"{key} #{i}"
                reset_bot(t, label)
    else:
        for key, toks in tokens.items():
            for i, t in enumerate(toks, 1):
                label = key if len(toks) == 1 else f"{key} #{i}"
                check_bot(t, label)

    print(f"\n{'='*70}")
    if not do_reset:
        print("To force-clean all bot state, run:")
        print("  python check_bots.py --reset")


if __name__ == "__main__":
    main()
