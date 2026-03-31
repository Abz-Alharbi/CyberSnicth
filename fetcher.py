"""
fetcher.py — RSS feed aggregator.
Pulls articles from all configured feeds and returns only new ones.
"""

import logging
import time
from dataclasses import dataclass, field
from typing import List

import feedparser
import requests

from config import RSS_FEEDS
from database import is_processed

logger = logging.getLogger(__name__)

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (compatible; HackerSnitchBot/1.0; "
        "+https://t.me/HackerSnitchBot)"
    )
}


@dataclass
class Article:
    title: str
    url: str
    summary: str
    source: str
    published: str = ""
    tags: List[str] = field(default_factory=list)


def fetch_rss_articles() -> List[Article]:
    """Fetch all RSS feeds and return new (unseen) articles."""
    new_articles: List[Article] = []

    for source_name, feed_url in RSS_FEEDS:
        try:
            logger.info("Fetching RSS: %s", source_name)
            resp = requests.get(feed_url, headers=HEADERS, timeout=15)
            resp.raise_for_status()
            feed = feedparser.parse(resp.content)

            for entry in feed.entries:
                url = getattr(entry, "link", "")
                if not url or is_processed(url):
                    continue

                title   = getattr(entry, "title", "No title")
                summary = getattr(entry, "summary", "") or getattr(entry, "description", "")
                # Strip basic HTML tags from summary
                summary = _strip_html(summary)[:800]

                published = ""
                if hasattr(entry, "published"):
                    published = entry.published

                tags = [t.term for t in getattr(entry, "tags", []) if hasattr(t, "term")]

                new_articles.append(
                    Article(
                        title=title,
                        url=url,
                        summary=summary,
                        source=source_name,
                        published=published,
                        tags=tags,
                    )
                )

            time.sleep(0.5)   # be polite to feed servers

        except Exception as exc:
            logger.warning("Failed to fetch %s: %s", source_name, exc)

    logger.info("RSS fetch complete — %d new articles found", len(new_articles))
    return new_articles


def _strip_html(text: str) -> str:
    """Very lightweight HTML tag remover (no dependencies)."""
    import re
    text = re.sub(r"<[^>]+>", "", text)
    text = re.sub(r"&amp;", "&", text)
    text = re.sub(r"&lt;", "<", text)
    text = re.sub(r"&gt;", ">", text)
    text = re.sub(r"&nbsp;", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text
