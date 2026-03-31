"""
cve_fetcher.py — Pulls recent CVEs from the NVD API (last N hours).
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import List, Optional

import requests

from config import NVD_API_URL, CVE_LOOKBACK_HOURS
from database import is_processed

logger = logging.getLogger(__name__)


@dataclass
class CVEItem:
    cve_id: str
    description: str
    cvss_score: Optional[float]
    cvss_severity: str
    published: str
    url: str
    weaknesses: List[str] = field(default_factory=list)


def fetch_recent_cves() -> List[CVEItem]:
    """Return new CVEs published within the last CVE_LOOKBACK_HOURS."""
    now   = datetime.now(timezone.utc)
    start = now - timedelta(hours=CVE_LOOKBACK_HOURS)

    params = {
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate":   now.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": 100,
    }

    try:
        logger.info("Fetching NVD CVEs (last %dh)…", CVE_LOOKBACK_HOURS)
        resp = requests.get(NVD_API_URL, params=params, timeout=30)
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        logger.error("NVD API error: %s", exc)
        return []

    results: List[CVEItem] = []
    for vuln in data.get("vulnerabilities", []):
        cve    = vuln.get("cve", {})
        cve_id = cve.get("id", "")
        url    = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

        if not cve_id or is_processed(url):
            continue

        # Description
        desc = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break

        # CVSS score (prefer v3.1, fall back to v3.0 then v2)
        cvss_score = None
        cvss_severity = "UNKNOWN"
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                m = metrics[key][0]
                cvss_data = m.get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                cvss_severity = cvss_data.get("baseSeverity", "UNKNOWN")
                break

        # CWE weaknesses
        weaknesses = []
        for w in cve.get("weaknesses", []):
            for desc_item in w.get("description", []):
                if desc_item.get("lang") == "en":
                    weaknesses.append(desc_item.get("value", ""))

        results.append(
            CVEItem(
                cve_id=cve_id,
                description=desc[:600],
                cvss_score=cvss_score,
                cvss_severity=cvss_severity,
                published=cve.get("published", ""),
                url=url,
                weaknesses=weaknesses,
            )
        )

    logger.info("NVD fetch complete — %d new CVEs found", len(results))
    return results
