"""
digest_sender.py — Three daily sends:

  07:00  CVE Summary    — one message, 5–10 CVEs listed by name + product only
  08:00  News Digest 1  — one message, top 4–5 news items (full summary each)
  16:00  News Digest 2  — one message, next 4–5 news items (no repeats)

News dedup: title similarity check prevents same story from different sources
            appearing twice across both digests.
Character limit: each message is validated before sending; items are dropped
                 one by one from the bottom until it fits within 4096 chars.
"""

import logging
import time
from datetime import datetime

import requests

import database
from config import (
    TELEGRAM_TOKEN, CHANNEL_ID,
    CVE_DIGEST_MAX, CVE_DIGEST_MIN,
    NEWS_PER_DIGEST,
)

logger  = logging.getLogger(__name__)
MAX_LEN = 4000   # safe Telegram ceiling

CATEGORY_ICONS = {
    "ransomware":    "🔒",
    "vulnerability": "🛡️",
    "breach":        "💀",
    "malware":       "🦠",
    "nation-state":  "🌐",
    "general":       "📰",
}

CATEGORY_WEIGHT = {
    "ransomware":    10,
    "nation-state":  9,
    "breach":        8,
    "vulnerability": 7,
    "malware":       6,
    "general":       3,
}

CVSS_ICONS = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🟢",
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _e(text: str) -> str:
    special = r"\_*[]()~`>#+-=|{}.!"
    return "".join(f"\\{c}" if c in special else c for c in str(text))


def _news_score(item: dict) -> float:
    sev    = item.get("severity", 0)
    weight = CATEGORY_WEIGHT.get(item.get("category", "general"), 3)
    actors = len(item.get("threat_actors", []) or [])
    return sev * 0.6 + weight * 3 + actors * 2


def _similar(a: str, b: str) -> bool:
    """True if two titles share 5+ consecutive words — same story, different source."""
    wa = a.lower().split()
    wb = set(b.lower().split())
    for i in range(len(wa) - 4):
        if all(w in wb for w in wa[i:i+5]):
            return True
    return False


def _dedupe_news(items: list) -> list:
    """Remove near-duplicate stories (same event, different source)."""
    seen, out = [], []
    for item in items:
        title = item["title"]
        if any(_similar(title, s) for s in seen):
            logger.info("Dedup skip (similar title): %s", title)
            continue
        seen.append(title)
        out.append(item)
    return out


def _send(text: str) -> bool:
    if len(text) > MAX_LEN:
        logger.error("Message too long (%d chars) — aborting send", len(text))
        return False
    try:
        resp = requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
            json={
                "chat_id":    CHANNEL_ID,
                "text":       text,
                "parse_mode": "MarkdownV2",
                "disable_web_page_preview": True,
            },
            timeout=20,
        )
        result = resp.json()
        if not result.get("ok"):
            logger.error("Telegram error: %s", result.get("description"))
            return False
        return True
    except Exception as exc:
        logger.error("Telegram send failed: %s", exc)
        return False


# ── CVE summary (07:00) ───────────────────────────────────────────────────────

def _extract_product(iocs: dict) -> str:
    """Pull the first affected system name from iocs, or empty string."""
    systems = iocs.get("affected_systems", []) if isinstance(iocs, dict) else []
    return systems[0] if systems else ""


def _build_cve_summary(cves: list) -> str:
    today    = datetime.now().strftime("%B %d, %Y")
    dow      = datetime.now().strftime("%A")
    lines    = [
        f"🛡️ *CVE Daily Summary*",
        f"📅 {_e(dow)}, {_e(today)}",
        f"",
        f"_Top {_e(str(len(cves)))} vulnerabilities published in the last 24 hours\\._",
        f"",
        f"━━━━━━━━━━━━━━━━━━━━",
        f"",
    ]
    for cve in cves:
        cve_id  = _e(cve["title"])
        score   = cve.get("cvss_score")
        sev     = cve.get("cvss_severity", "UNKNOWN")
        icon    = CVSS_ICONS.get(sev.upper(), "⚪")
        product = _extract_product(cve.get("iocs") or {})
        prod_str = f" \\[{_e(product)}\\]" if product else ""
        score_str = f" · CVSS {_e(str(score))}" if score else ""
        lines.append(f"{icon} {cve_id}{prod_str}{score_str}")

    lines += [
        f"",
        f"━━━━━━━━━━━━━━━━━━━━",
        f"\\#CVE \\#Cybersecurity \\#ThreatIntelligence \\#CyberSnitch",
    ]
    return "\n".join(lines)


def send_cve_summary() -> bool:
    """07:00 — Send one-message CVE list (names + product only)."""
    if database.was_digest_sent_today("cve_summary"):
        logger.info("CVE summary already sent today — skipping.")
        return False

    cves = database.inbox_pending(item_type="cve")
    # Sort by CVSS score descending
    cves.sort(key=lambda x: (x.get("cvss_score") or 0), reverse=True)

    if len(cves) < CVE_DIGEST_MIN:
        logger.info("CVE summary skipped — only %d CVEs (min %d).", len(cves), CVE_DIGEST_MIN)
        return False

    top_cves = cves[:CVE_DIGEST_MAX]
    msg      = _build_cve_summary(top_cves)

    if _send(msg):
        database.inbox_mark_used([c["uid"] for c in top_cves])
        database.log_digest("cve_summary", len(top_cves))
        logger.info("✅ CVE summary sent: %d CVEs", len(top_cves))
        return True

    logger.error("❌ CVE summary failed to send")
    return False


# ── News digest builder ───────────────────────────────────────────────────────

def _build_news_digest(items: list, label: str) -> str:
    today = datetime.now().strftime("%B %d, %Y")
    dow   = datetime.now().strftime("%A")
    lines = [
        f"📡 *CyberSnitch Intel Digest* — {_e(label)}",
        f"📅 {_e(dow)}, {_e(today)}",
        f"",
        f"━━━━━━━━━━━━━━━━━━━━",
    ]
    for item in items:
        cat      = item.get("category", "general")
        icon     = CATEGORY_ICONS.get(cat, "📰")
        title    = _e(item["title"])
        source   = _e(item.get("source", ""))
        summary  = _e(item.get("summary", "No summary available."))
        takeaway = _e(item.get("key_takeaway", ""))
        url      = item.get("url", "")
        actors   = item.get("threat_actors") or []
        sev      = item.get("severity", 0)
        sev_icon = "🔴" if sev >= 80 else "🟠" if sev >= 60 else "🟡" if sev >= 30 else "🟢"
        a_str    = f" · 👤 {_e(', '.join(actors[:2]))}" if actors else ""

        lines += [
            f"",
            f"{icon} *{title}*",
            f"{sev_icon} {sev}/100   📡 {source}{a_str}",
            f"",
            f"📋 *Summary*",
            f"{summary}",
        ]
        if takeaway:
            lines += [f"💡 _{takeaway}_"]
        lines += [
            f"🔗 [Read More]({url})",
            f"━━━━━━━━━━━━━━━━━━━━",
        ]

    lines += [
        f"\\#Cybersecurity \\#ThreatIntelligence \\#InfoSec \\#CyberSnitch",
    ]
    return "\n".join(lines)


def _fit_to_limit(items: list, label: str) -> tuple:
    """
    Drop lowest-scored items one by one until message fits within MAX_LEN.
    Returns (final_items, message_text).
    """
    while items:
        msg = _build_news_digest(items, label)
        if len(msg) <= MAX_LEN:
            return items, msg
        logger.warning("Message too long (%d) — dropping lowest-scored item", len(msg))
        items = items[:-1]   # remove last (lowest scored) item
    return [], ""


# ── News digest sends (08:00 and 16:00) ──────────────────────────────────────

def send_news_digest(digest_num: int) -> bool:
    """
    digest_num=1 → 08:00 digest (top NEWS_PER_DIGEST items)
    digest_num=2 → 16:00 digest (next NEWS_PER_DIGEST items, no repeats)
    """
    digest_type = f"news_{digest_num}"
    label       = "Morning Edition" if digest_num == 1 else "Afternoon Edition"

    if database.was_digest_sent_today(digest_type):
        logger.info("%s already sent today — skipping.", label)
        return False

    # Get all pending news, deduped, sorted by score
    all_news = database.inbox_pending(item_type="article")
    all_news = _dedupe_news(all_news)
    all_news.sort(key=_news_score, reverse=True)

    if not all_news:
        logger.info("%s skipped — no news in inbox.", label)
        return False

    # Digest 1 = top slice, Digest 2 = next slice
    start = (digest_num - 1) * NEWS_PER_DIGEST
    end   = start + NEWS_PER_DIGEST
    items = all_news[start:end]

    if not items:
        logger.info("%s skipped — not enough items for digest %d.", label, digest_num)
        return False

    # Trim to fit Telegram limit
    items, msg = _fit_to_limit(items, label)

    if not items or not msg:
        logger.error("%s — could not fit any items within limit.", label)
        return False

    if _send(msg):
        database.inbox_mark_used([i["uid"] for i in items])
        database.log_digest(digest_type, len(items))
        logger.info("✅ %s sent: %d items (%d chars)", label, len(items), len(msg))
        return True

    logger.error("❌ %s failed to send", label)
    return False