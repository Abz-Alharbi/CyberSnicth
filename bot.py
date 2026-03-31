"""
bot.py — HackerSnitch Pro · Daily Digest Scheduler

Schedule:
  07:00  → CVE summary      (1 message, 5–10 CVEs, names + product only)
  08:00  → News Digest 1    (1 message, top 4–5 news, full summaries)
  16:00  → News Digest 2    (1 message, next 4–5 news, no repeats)
  Instant → Critical CVE alert if CVSS >= 9.0 (fired inside collector)

Collection: silent fetch + AI analysis every 2 hours, no posting.
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
    """Check current time and fire any digest that is due and not yet sent today."""
    now  = datetime.now()
    hour = now.hour

    # 07:00 — CVE summary
    if hour >= CVE_DIGEST_HOUR:
        if not database.was_digest_sent_today("cve_summary"):
            logger.info("⏰ 07:00 trigger — sending CVE summary…")
            digest_sender.send_cve_summary()

    # 08:00 — Morning news digest
    if hour >= NEWS_DIGEST_HOUR_1:
        if not database.was_digest_sent_today("news_1"):
            logger.info("⏰ 08:00 trigger — sending Morning Digest…")
            digest_sender.send_news_digest(1)

    # 16:00 — Afternoon news digest
    if hour >= NEWS_DIGEST_HOUR_2:
        if not database.was_digest_sent_today("news_2"):
            logger.info("⏰ 16:00 trigger — sending Afternoon Digest…")
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
    logger.info("   Critical CVEs → instant alert (CVSS >= 9.0)")
    logger.info("=" * 60)

    while True:
        try:
            # 1. Silent collection
            collector.run_collection()

            # 2. Fire any due digests
            _check_and_send()

            # 3. Log stats
            s = database.stats()
            logger.info(
                "📊 processed: %d | pending news: %d | pending CVEs: %d | digests sent: %d",
                s["total_processed"], s["pending_news"],
                s["pending_cves"],    s["digests_sent"],
            )

        except KeyboardInterrupt:
            logger.info("Stopped.")
            break
        except Exception as exc:
            logger.exception("Unhandled error: %s", exc)

        sleep_secs = FETCH_INTERVAL_MINUTES * 60
        logger.info("😴 Sleeping %d min…\n", FETCH_INTERVAL_MINUTES)
        time.sleep(sleep_secs)


if __name__ == "__main__":
    main()