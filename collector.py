"""
collector.py — Silent background collector.

Runs every FETCH_INTERVAL_MINUTES. Fetches RSS + CVEs, analyses with Groq,
stores results in the inbox. Posts NOTHING except critical CVE instant alerts.
"""

import logging
import time
from datetime import datetime, timedelta, timezone

import feedparser
import requests

import intel
import database
from config import (
    RSS_FEEDS, NVD_API_URL, CVE_LOOKBACK_HOURS,
    DIGEST_MIN_SEV,
    MAX_ANALYSE_PER_RUN, TELEGRAM_TOKEN, CHANNEL_ID, BOT_CHAT_ID
)

logger = logging.getLogger(__name__)
HEADERS = {"User-Agent": "HackerSnitchBot/3.0"}


# ── HTML stripper ─────────────────────────────────────────────────────────────

def _strip(text: str) -> str:
    import re
    text = re.sub(r"<[^>]+>", "", text)
    for h, r in [("&amp;","&"),("&lt;","<"),("&gt;",">"),("&nbsp;"," ")]:
        text = text.replace(h, r)
    return re.sub(r"\s+", " ", text).strip()


# ── Escape for MarkdownV2 ─────────────────────────────────────────────────────

def _e(t: str) -> str:
    special = r"\_*[]()~`>#+-=|{}.!"
    return "".join(f"\\{c}" if c in special else c for c in str(t))


# ── RSS collector ─────────────────────────────────────────────────────────────

def collect_rss() -> int:
    """Fetch RSS feeds, analyse new articles, store in inbox. Returns count added."""
    new_items = []

    for source_name, feed_url in RSS_FEEDS:
        try:
            resp = requests.get(feed_url, headers=HEADERS, timeout=15)
            resp.raise_for_status()
            feed = feedparser.parse(resp.content)
            for entry in feed.entries:
                url = getattr(entry, "link", "")
                if not url or database.is_seen(url):
                    continue
                title   = getattr(entry, "title", "No title")
                summary = _strip(
                    getattr(entry, "summary", "") or getattr(entry, "description", "")
                )[:800]
                new_items.append({
                    "title": title, "url": url,
                    "summary": summary, "source": source_name
                })
            time.sleep(0.5)
        except Exception as exc:
            logger.warning("RSS fetch error %s: %s", source_name, exc)

    logger.info("RSS: %d new articles to analyse", len(new_items))
    added = 0

    for item in new_items[:MAX_ANALYSE_PER_RUN]:
        ai = intel.analyse_article(item["title"], item["summary"], item["source"])
        if not ai:
            database.mark_processed(item["url"], item["title"], item["source"])
            continue

        sev = ai.get("severity", 0)
        if sev < DIGEST_MIN_SEV:
            database.mark_processed(item["url"], item["title"], item["source"])
            continue

        stored = database.inbox_add({
            "title":         item["title"],
            "url":           item["url"],
            "source":        item["source"],
            "item_type":     "article",
            "category":      ai.get("category", "general"),
            "severity":      sev,
            "cvss_score":    None,
            "cvss_severity": "",
            "summary":       ai.get("summary", ""),
            "key_takeaway":  ai.get("key_takeaway", ""),
            "threat_actors": ai.get("threat_actors", []),
            "iocs":          ai.get("iocs", {}),
        })
        if stored:
            added += 1
            logger.info("📥 Inbox: [sev=%d] %s", sev, item["title"])

    return added


# ── CVE collector ─────────────────────────────────────────────────────────────

def collect_cves() -> int:
    """Fetch NVD CVEs, analyse, store or instantly alert if critical."""
    now   = datetime.now(timezone.utc)
    start = now - timedelta(hours=CVE_LOOKBACK_HOURS)
    params = {
        "pubStartDate":   start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate":     now.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": 100,
    }
    try:
        resp = requests.get(NVD_API_URL, params=params, timeout=30)
        resp.raise_for_status()
        vulns = resp.json().get("vulnerabilities", [])
    except Exception as exc:
        logger.error("NVD API error: %s", exc)
        return 0

    # Sort by CVSS descending — process highest risk first
    def _score(v):
        metrics = v.get("cve", {}).get("metrics", {})
        for k in ("cvssMetricV31","cvssMetricV30","cvssMetricV2"):
            if metrics.get(k):
                return metrics[k][0].get("cvssData", {}).get("baseScore", 0) or 0
        return 0

    vulns_sorted = sorted(vulns, key=_score, reverse=True)
    added = 0

    for vuln in vulns_sorted[:MAX_ANALYSE_PER_RUN]:
        cve    = vuln.get("cve", {})
        cve_id = cve.get("id", "")
        url    = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

        if not cve_id or database.is_seen(url):
            continue

        # Description
        desc = next(
            (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), ""
        )

        # CVSS
        cvss_score, cvss_sev = None, "UNKNOWN"
        for key in ("cvssMetricV31","cvssMetricV30","cvssMetricV2"):
            m = cve.get("metrics", {}).get(key, [])
            if m:
                d = m[0].get("cvssData", {})
                cvss_score = d.get("baseScore")
                cvss_sev   = d.get("baseSeverity", "UNKNOWN")
                break

        # Skip anything below HIGH
        if (cvss_score or 0) < 7.0:
            database.mark_processed(url, cve_id, "NVD")
            continue

        weaknesses = [
            d["value"] for w in cve.get("weaknesses", [])
            for d in w.get("description", []) if d.get("lang") == "en"
        ]

        logger.info("Analysing CVE: %s (CVSS %.1f)", cve_id, cvss_score or 0)
        ai = intel.analyse_cve(cve_id, desc[:600], cvss_score, cvss_sev, weaknesses)
        if not ai:
            database.mark_processed(url, cve_id, "NVD")
            continue

        item = {
            "title":              cve_id,
            "url":                url,
            "source":             "NVD",
            "item_type":          "cve",
            "category":           "vulnerability",
            "severity":           ai.get("severity", 0),
            "cvss_score":         cvss_score,
            "cvss_severity":      cvss_sev,
            "summary":            ai.get("summary", ""),
            "key_takeaway":       ai.get("key_takeaway", ""),
            "threat_actors":      [],
            "iocs":               {
                "affected_systems":    ai.get("affected_systems", []),
                "exploitation_likelihood": ai.get("exploitation_likelihood", ""),
                "recommended_action":  ai.get("recommended_action", ""),
            },
        }

        # All CVEs go into inbox for the 07:00 summary
        if database.inbox_add(item):
            added += 1
            logger.info("📥 Inbox CVE: %s (CVSS %.1f)", cve_id, cvss_score or 0)

    return added


# ── Main collection run ───────────────────────────────────────────────────────

def run_collection() -> None:
    logger.info("── Collection cycle starting ──")
    rss_added = collect_rss()
    cve_added = collect_cves()
    pending   = database.inbox_count_pending()
    logger.info("── Collection done: +%d RSS, +%d CVE | inbox total: %d ──",
                rss_added, cve_added, pending)