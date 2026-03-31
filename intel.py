"""
intel.py — Groq llama-3.3-70b threat intelligence engine.
Compact prompts to stay within free-tier token limits.
"""

import json
import time
import logging
from typing import Any, Dict, Optional

import requests
from config import GROQ_API_KEY, GROQ_MODEL, GROQ_CALL_DELAY

logger = logging.getLogger(__name__)
GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"

_ARTICLE_SYSTEM = """Cybersecurity analyst. Analyse article. Return ONLY JSON, no markdown:
{"severity":<0-100>,"category":<"ransomware"|"vulnerability"|"breach"|"malware"|"nation-state"|"general">,"summary":"<2-3 sentence technical summary>","key_takeaway":"<1 sentence action>","iocs":{"cves":[],"domains":[],"malware_names":[]},"threat_actors":[]}"""

_CVE_SYSTEM = """Vulnerability analyst. Analyse CVE. Return ONLY JSON, no markdown:
{"severity":<0-100>,"summary":"<2-3 sentence technical summary>","key_takeaway":"<1 sentence action>","affected_systems":[],"exploitation_likelihood":"<low|medium|high|critical>","recommended_action":"<1 sentence>"}"""


def _call_groq(system: str, user: str) -> Optional[Dict[str, Any]]:
    time.sleep(GROQ_CALL_DELAY)   # always pace before calling
    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type":  "application/json",
    }
    payload = {
        "model": GROQ_MODEL,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user",   "content": user[:600]},
        ],
        "temperature": 0.1,
        "max_tokens":  400,
    }
    for attempt in range(2):
        try:
            resp = requests.post(GROQ_URL, headers=headers, json=payload, timeout=30)
            if resp.status_code == 429:
                wait = int(resp.headers.get("retry-after", 65))
                logger.warning("Groq 429 — waiting %ds", wait)
                if attempt == 0:
                    time.sleep(wait)
                    continue
                return None
            resp.raise_for_status()
            raw = resp.json()["choices"][0]["message"]["content"].strip()
            if "```" in raw:
                parts = raw.split("```")
                raw = parts[1][4:] if parts[1].startswith("json") else parts[1]
            return json.loads(raw.strip())
        except json.JSONDecodeError:
            logger.error("Groq non-JSON response")
            return None
        except Exception as exc:
            logger.error("Groq error: %s", exc)
            return None
    return None


def analyse_article(title: str, summary: str, source: str) -> Optional[Dict]:
    return _call_groq(_ARTICLE_SYSTEM,
                      f"Source:{source}\nTitle:{title}\n{summary[:400]}")


def analyse_cve(cve_id: str, description: str, cvss_score,
                cvss_severity: str, weaknesses: list) -> Optional[Dict]:
    user = (f"CVE:{cve_id} CVSS:{cvss_score}({cvss_severity})\n"
            f"CWE:{','.join(weaknesses[:2]) or 'N/A'}\n{description[:400]}")
    return _call_groq(_CVE_SYSTEM, user)
