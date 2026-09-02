# CipherPoint — Production Deployment Checklist

## ⚠️ Before first deploy

### 1. Rotate all secrets (because `.env` was committed earlier)
- [ ] Generate new `SECRET_KEY`: `python -c "import secrets; print(secrets.token_urlsafe(64))"`
- [ ] Reset all 3 upload bot tokens via @BotFather (`/revoke`)
- [ ] Reset admin bot + report bot tokens
- [ ] Get new Turnstile keys from Cloudflare
- [ ] Update channel admin list (kick old bots, add new ones)

### 2. Render setup
1. Push to GitHub **without `.env`** (verify `.gitignore` first)
2. Render → New → Blueprint → select repo
3. Render will read `render.yaml` and create:
   - PostgreSQL database (free tier)
   - Web service from `backend/` folder
4. After deploy, go to **Environment** tab and fill in:
   - `TELEGRAM_BOT_TOKENS` (comma-separated, all 3)
   - `TELEGRAM_ADMIN_BOT_TOKEN`
   - `REPORT_BOT_TOKEN`
   - `TELEGRAM_CHANNEL_ID`
   - `TELEGRAM_ADMIN_CHAT_ID`
   - `SITE_KEY`, `CLOUDFLARE_SECRET_KEY`
5. Wait for deploy → open `https://cipherpoint.onrender.com/api/health`

### 3. Post-deploy smoke test
```bash
curl https://cipherpoint.onrender.com/api/health
# Login as admin (default password admin123 — change immediately!)
curl -X POST https://cipherpoint.onrender.com/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}'
```

### 5. Update Telegram bots with public URL
In `@BotFather`:
- `/setdomain` for each bot → set `cipherpoint.onrender.com`
- This enables the Login Widget for OTP and inline buttons

## Architecture
- Frontend: served by FastAPI StaticFiles on `/`
- Backend: FastAPI + gunicorn (1 worker due to polling threads)
- Database: Render PostgreSQL (free tier, persistent)
- Telegram: 5 bots (3 upload, 1 admin, 1 report)
- Polling/expiry: only in WORKER_ID=0 (single worker setup)

## Limitations of free tier
- Sleeps after 15 min inactivity (cold start ~30 sec)
- 750 hrs/month
- No persistent disk (Postgres bypasses this)

## Going to production-ready paid tier
- Increase gunicorn workers, deploy Redis, add CDN