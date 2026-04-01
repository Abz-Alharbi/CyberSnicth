"""
bot.py — HackerSnitch Pro · Daily Digest Scheduler

Schedule:
  07:00  → CVE summary      (1 message, 5–10 CVEs, names only)
  08:00  → News Digest 1    (1 message, top 4–5 news, full summaries)
  16:00  → News Digest 2    (1 message, next 4–5 news, no repeats)

Collection: silent fetch + AI analysis every 2 hours, no posting.

How the loop works:
  - Sleeps 60 seconds at a time (minute-level precision)
  - Every minute: checks if any digest is due → fires immediately if yes
  - Every 2 hours: runs the silent collection cycle
"""

import logging
import os
import time
from datetime import datetime

import collector
import digest_sender
import database
from config import (
    FETCH_INTERVAL_MINUTES,
    CVE_DIGEST_HOUR,
    NEWS_DIGEST_HOUR_1,
    NEWS_DIGEST_HOUR_2,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("bot")


def _check_and_send() -> None:
    """Fire any digest that is due and not yet sent today."""
    now  = datetime.now()
    hour = now.hour

    if hour >= CVE_DIGEST_HOUR:
        if not database.was_digest_sent_today("cve_summary"):
            logger.info("⏰ CVE summary trigger — sending…")
            digest_sender.send_cve_summary()

    if hour >= NEWS_DIGEST_HOUR_1:
        if not database.was_digest_sent_today("news_1"):
            logger.info("⏰ Morning digest trigger — sending…")
            digest_sender.send_news_digest(1)

    if hour >= NEWS_DIGEST_HOUR_2:
        if not database.was_digest_sent_today("news_2"):
            logger.info("⏰ Afternoon digest trigger — sending…")
            digest_sender.send_news_digest(2)


def main() -> None:
    os.makedirs("data", exist_ok=True)
    database.init_db()

    logger.info("=" * 60)
    logger.info("🛡️  HackerSnitch Pro — Daily Digest Mode")
    logger.info("   Collection every %d min", FETCH_INTERVAL_MINUTES)
    logger.info("   CVE summary   → %02d:00", CVE_DIGEST_HOUR)
    logger.info("   News digest 1 → %02d:00", NEWS_DIGEST_HOUR_1)
    logger.info("   News digest 2 → %02d:00", NEWS_DIGEST_HOUR_2)
    logger.info("=" * 60)

    # Track when the last collection ran
    last_collection_min = -FETCH_INTERVAL_MINUTES  # force immediate collection on startup

    while True:
        try:
            now         = datetime.now()
            elapsed_min = (time.monotonic() - _start_time) / 60

            # ── Collection: run every FETCH_INTERVAL_MINUTES ──────────────
            if elapsed_min - last_collection_min >= FETCH_INTERVAL_MINUTES:
                collector.run_collection()
                last_collection_min = elapsed_min

                s = database.stats()
                logger.info(
                    "📊 processed: %d | pending news: %d | pending CVEs: %d | digests sent: %d",
                    s["total_processed"], s["pending_news"],
                    s["pending_cves"],    s["digests_sent"],
                )

            # ── Digest check: runs every minute ──────────────────────────
            _check_and_send()

        except KeyboardInterrupt:
            logger.info("Stopped.")
            break
        except Exception as exc:
            logger.exception("Unhandled error: %s", exc)

        time.sleep(60)   # check every minute


# Record start time for elapsed tracking
_start_time = time.monotonic()

if __name__ == "__main__":
    main()