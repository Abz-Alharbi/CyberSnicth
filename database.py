"""
database.py — Extended schema for Daily Digest model.

Tables:
  - inbox      : articles/CVEs collected silently, waiting for digest
  - digest_log : one row per digest/CVE-summary sent (audit trail)
  - processed  : legacy dedup
"""

import json
import sqlite3
import hashlib
import logging
from config import DB_PATH

logger = logging.getLogger(__name__)


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with _connect() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS processed (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                uid          TEXT    UNIQUE NOT NULL,
                title        TEXT,
                source       TEXT,
                processed_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS inbox (
                uid                TEXT PRIMARY KEY,
                title              TEXT NOT NULL,
                url                TEXT NOT NULL,
                source             TEXT,
                item_type          TEXT DEFAULT 'article',
                category           TEXT DEFAULT 'general',
                severity           INTEGER DEFAULT 0,
                cvss_score         REAL,
                cvss_severity      TEXT,
                summary            TEXT,
                key_takeaway       TEXT,
                threat_actors      TEXT,
                iocs               TEXT,
                collected_at       DATETIME DEFAULT CURRENT_TIMESTAMP,
                included_in_digest INTEGER DEFAULT 0
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS digest_log (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                sent_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
                digest_type TEXT,
                item_count  INTEGER
            )
        """)
        conn.commit()

        # ── Migrate old digest_log if digest_type column is missing ──────
        cols = [r[1] for r in conn.execute("PRAGMA table_info(digest_log)").fetchall()]
        if "digest_type" not in cols:
            logger.info("Migrating digest_log — adding digest_type column…")
            conn.execute("ALTER TABLE digest_log ADD COLUMN digest_type TEXT")
            conn.execute("ALTER TABLE digest_log ADD COLUMN item_count  INTEGER")
            conn.commit()
            logger.info("Migration complete.")

    logger.info("Database initialised at %s", DB_PATH)


# ── Dedup ─────────────────────────────────────────────────────────────────────

def _uid(url: str) -> str:
    return hashlib.sha256(url.encode()).hexdigest()[:32]


def is_seen(url: str) -> bool:
    uid = _uid(url)
    with _connect() as conn:
        a = conn.execute("SELECT 1 FROM inbox     WHERE uid=?", (uid,)).fetchone()
        b = conn.execute("SELECT 1 FROM processed WHERE uid=?", (uid,)).fetchone()
    return bool(a or b)


def mark_processed(url: str, title: str = "", source: str = "") -> None:
    uid = _uid(url)
    with _connect() as conn:
        try:
            conn.execute(
                "INSERT INTO processed (uid, title, source) VALUES (?,?,?)",
                (uid, title, source)
            )
            conn.commit()
        except sqlite3.IntegrityError:
            pass


# ── Inbox ─────────────────────────────────────────────────────────────────────

def inbox_add(item: dict) -> bool:
    uid = _uid(item["url"])
    with _connect() as conn:
        try:
            conn.execute("""
                INSERT INTO inbox
                  (uid, title, url, source, item_type, category, severity,
                   cvss_score, cvss_severity, summary, key_takeaway,
                   threat_actors, iocs)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                uid,
                item.get("title", ""),
                item.get("url", ""),
                item.get("source", ""),
                item.get("item_type", "article"),
                item.get("category", "general"),
                item.get("severity", 0),
                item.get("cvss_score"),
                item.get("cvss_severity", ""),
                item.get("summary", ""),
                item.get("key_takeaway", ""),
                json.dumps(item.get("threat_actors", [])),
                json.dumps(item.get("iocs", {})),
            ))
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False


def inbox_pending(item_type: str = None) -> list:
    with _connect() as conn:
        if item_type:
            rows = conn.execute("""
                SELECT * FROM inbox
                WHERE included_in_digest = 0 AND item_type = ?
                ORDER BY severity DESC, collected_at DESC
            """, (item_type,)).fetchall()
        else:
            rows = conn.execute("""
                SELECT * FROM inbox
                WHERE included_in_digest = 0
                ORDER BY severity DESC, collected_at DESC
            """).fetchall()

    result = []
    for r in rows:
        d = dict(r)
        try:    d["threat_actors"] = json.loads(d.get("threat_actors") or "[]")
        except: d["threat_actors"] = []
        try:    d["iocs"] = json.loads(d.get("iocs") or "{}")
        except: d["iocs"] = {}
        result.append(d)
    return result


def inbox_mark_used(uids: list) -> None:
    with _connect() as conn:
        conn.executemany(
            "UPDATE inbox SET included_in_digest=1 WHERE uid=?",
            [(uid,) for uid in uids]
        )
        conn.commit()


def inbox_count_pending(item_type: str = None) -> int:
    with _connect() as conn:
        if item_type:
            return conn.execute(
                "SELECT COUNT(*) FROM inbox WHERE included_in_digest=0 AND item_type=?",
                (item_type,)
            ).fetchone()[0]
        return conn.execute(
            "SELECT COUNT(*) FROM inbox WHERE included_in_digest=0"
        ).fetchone()[0]


def log_digest(digest_type: str, item_count: int) -> None:
    with _connect() as conn:
        conn.execute(
            "INSERT INTO digest_log (digest_type, item_count) VALUES (?,?)",
            (digest_type, item_count)
        )
        conn.commit()


def was_digest_sent_today(digest_type: str) -> bool:
    with _connect() as conn:
        row = conn.execute("""
            SELECT 1 FROM digest_log
            WHERE digest_type = ?
              AND DATE(sent_at) = DATE('now')
        """, (digest_type,)).fetchone()
    return row is not None


def stats() -> dict:
    with _connect() as conn:
        total  = conn.execute("SELECT COUNT(*) FROM processed").fetchone()[0]
        p_news = conn.execute(
            "SELECT COUNT(*) FROM inbox WHERE included_in_digest=0 AND item_type='article'"
        ).fetchone()[0]
        p_cves = conn.execute(
            "SELECT COUNT(*) FROM inbox WHERE included_in_digest=0 AND item_type='cve'"
        ).fetchone()[0]
        digests = conn.execute("SELECT COUNT(*) FROM digest_log").fetchone()[0]
    return {
        "total_processed": total,
        "pending_news":    p_news,
        "pending_cves":    p_cves,
        "digests_sent":    digests,
    }