# CipherPoint

**CTF (Capture The Flag) Platform** - FastAPI + Turso (libSQL) + Telegram integration

## Features

- **Challenges** - Create/solve CTF challenges with hints, flags, points
- **Community CTFs** - Users submit challenges (weekly quota, auto-expiry)
- **Leaderboard** - Rank points, coins, weekly/monthly rankings
- **Auth** - JWT (access + refresh), bcrypt, Turnstile CAPTCHA, rate limits
- **Admin Panel** - User management, bans, challenge moderation, reports
- **Telegram Bot** - Notifications (mentions, reports, admin alerts), media upload
- **Comments** - Threaded discussions on challenges with @mentions
- **Intel Vault** - Published articles/guides
- **Maintenance Mode** - Scheduled downtime with admin bypass

## Tech Stack

- **Backend**: FastAPI, SQLAlchemy, Pydantic
- **Database**: Turso (libSQL/SQLite)
- **Auth**: PyJWT, bcrypt
- **Telegram**: Bot API (polling + webhook)
- **Security**: CSP, HSTS, rate limiting, IP tracking (Cloudflare proxy)

## Quick Start

```bash
cd backend
cp .env.example .env   # fill in secrets
pip install -r requirements.txt
uvicorn main:app --reload
```

## Environment Variables (key ones)

| Variable | Description |
|----------|-------------|
| `SECRET_KEY` | JWT signing key (64+ chars in prod) |
| `TURSO_DATABASE_URL` | libSQL connection string |
| `TURSO_AUTH_TOKEN` | Database auth token |
| `TELEGRAM_BOT_TOKENS` | Comma-separated upload bot tokens |
| `TELEGRAM_ADMIN_BOT_TOKEN` | Admin notification bot |
| `TELEGRAM_ADMIN_CHAT_ID` | Admin chat ID for alerts |
| `TURNSTILE_SECRET_KEY` | Cloudflare Turnstile secret |
| `ADMIN_PASSWORD` | Initial admin password (12+ chars) |

## Deployment

- **Render** - `render.yaml` included (web service + cron for expiry)
- **Docker** - `backend/Dockerfile` available
- Set `ENV=production` and all secrets in platform env vars

## Project Structure

```
backend/
├── main.py              # FastAPI app + all routes
├── models.py            # SQLAlchemy models
├── database.py          # DB connection (Turso)
├── security.py          # Password hashing, rate limits
├── telegram_proxy.py    # Telegram Bot API wrappers
├── seed.py              # Dev data seeding
├── frontend/            # Static HTML/JS/CSS
└── requirements.txt
```

## API Endpoints (main)

- `POST /api/auth/signup` / `login` / `refresh` / `logout`
- `GET /api/challenges` / `POST /api/challenges` (admin)
- `POST /api/challenges/{id}/submit` - submit flag
- `POST /api/challenges/{id}/hint` - unlock hint
- `GET/POST /api/challenges/{id}/comments`
- `GET /api/leaderboard`
- `GET /api/intel` - articles
- `GET /api/admin/*` - admin only

## License

MIT