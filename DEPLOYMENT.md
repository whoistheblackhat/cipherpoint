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

## Cipher Day event

Cipher Day has its own environment switch and scheduled UTC window. It defaults
to hidden/off. Configure these values in the hosting dashboard (Botkeep for the
live site); changing environment variables may trigger a redeploy:

- `CIPHER_DAY_ENV`: `true` to enable the event, otherwise `false`.
- `CIPHER_DAY_STARTS_AT` / `CIPHER_DAY_ENDS_AT`: ISO-8601 UTC timestamps, e.g.
  `2026-11-20T12:00:00Z` and `2026-11-21T12:00:00Z`.
- `CIPHER_DAY_CHALLENGE_ID`: ID of the curated challenge created in Admin.
  Set that challenge's reward to at least 500 points and its correct flag to
  the event answer. The normal solve/leaderboard transaction is reused.
- `CIPHER_DAY_ASSET_BASE_URL`: HTTPS root of a public static asset tree with
  `v86/build/libv86.js`, `v86/build/v86.wasm`, `v86/bios/`, and
  `images/cipher-day-fs.json` plus `images/cipher-day-rootfs-flat/`.

The static asset host must allow browser CORS requests from the CipherPoint
site. The event pages and submission endpoint are gated by the switch/window;
the existing site-wide maintenance switch is not used. Turning the event off
prevents future launches and flag submissions, but cannot revoke files already
downloaded into a learner's browser.

The local build directory is about 642 MiB, but that includes redundant build
outputs. `cipher-day-rootfs.tar` (~474 MiB) is a build/export intermediate and
is not required by the browser. The browser runtime needs the compressed
filesystem chunks (~166 MiB), filesystem manifest, and v86 runtime assets
(about 2 MiB). A learner downloads the filesystem from the configured static
host; it is not copied into the Botkeep application deployment.

A separate `Cipher-machines` GitHub repository can version the build recipe and
publish machine artifacts. A GitHub Release download is a single archive, not
the directory-style CORS-enabled static tree v86 requests for the filesystem
chunks. Extract/publish that release to a static host such as a CORS-configured
object store/CDN, then point `CIPHER_DAY_ASSET_BASE_URL` at that tree. Verify
the host allows `fetch` from the browser before enabling the event.

## Limitations of free tier
- Sleeps after 15 min inactivity (cold start ~30 sec)
- 750 hrs/month
- No persistent disk (Postgres bypasses this)

## Going to production-ready paid tier
- Increase gunicorn workers, deploy Redis, add CDN