# ============================================================
#  HackerSnitch Pro — Configuration
#  Secrets are loaded from .env file (never commit .env)
# ============================================================

import os
from dotenv import load_dotenv

load_dotenv()

# Telegram
TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN", "")
CHANNEL_ID     = os.getenv("CHANNEL_ID", "")
BOT_CHAT_ID    = os.getenv("BOT_CHAT_ID", "")

# Groq AI
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL   = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")

# RSS Feeds — highest signal-to-noise sources only
RSS_FEEDS = [
    ("KrebsOnSecurity", "https://krebsonsecurity.com/feed/"),
    ("DarkReading",     "https://www.darkreading.com/rss.xml"),
    ("SecurityWeek",    "https://feeds.feedburner.com/securityweek"),
    ("UK NCSC",         "https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml"),
]

# NVD CVE API
NVD_API_URL        = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVE_LOOKBACK_HOURS = 24

# ── Schedule ──────────────────────────────────────────────────────────────────
CVE_DIGEST_HOUR    = 7     # 07:00 — CVE summary (names only)
NEWS_DIGEST_HOUR_1 = 8     # 08:00 — Morning news digest
NEWS_DIGEST_HOUR_2 = 16    # 16:00 — Afternoon news digest

# ── Limits ────────────────────────────────────────────────────────────────────
CVE_DIGEST_MAX     = 10    # max CVEs in the 07:00 summary
CVE_DIGEST_MIN     = 5     # min CVEs needed to bother sending
NEWS_PER_DIGEST    = 5     # news items per digest
DIGEST_MIN_SEV     = 40    # minimum AI severity score to enter inbox

# ── Collection ────────────────────────────────────────────────────────────────
FETCH_INTERVAL_MINUTES = 120  # silent collection every 2 hours

# ── Groq rate limiting ────────────────────────────────────────────────────────
GROQ_CALL_DELAY     = 8   # seconds between Groq API calls
MAX_ANALYSE_PER_RUN = 6   # max items sent to Groq per cycle

# Database
DB_PATH = "data/articles.db"