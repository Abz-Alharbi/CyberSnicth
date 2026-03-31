"""
formatter.py — Telegram MarkdownV2 message formatter.

v2 changes:
  - Executive + Technical summaries merged into one "📋 Summary" block
  - 3 distinct layouts:
      • CRITICAL CVE  — prominent CVSS bar + red header
      • HIGH-IMPACT NEWS (sev >= 70 or ransomware/nation-state/breach) — bold alert style
      • INTEL BRIEF (everything else) — compact, clean
"""

from typing import Any, Dict, Optional

# ── Icons ─────────────────────────────────────────────────────────────────────

CATEGORY_ICONS = {
    "ransomware":    "🔒",
    "vulnerability": "🛡️",
    "breach":        "💀",
    "malware":       "🦠",
    "nation-state":  "🌐",
    "general":       "📰",
}

SOURCE_ICONS = {
    "DarkReading":     "📡",
    "KrebsOnSecurity": "🕵️",
    "The Register":    "📰",
    "SecurityWeek":    "🔐",
    "CSO Online":      "💼",
    "RiskyBiz":        "⚠️",
    "UK NCSC":         "🇬🇧",
    "NVD":             "🗃️",
}

EXPLOIT_ICONS = {
    "low":      "🟢",
    "medium":   "🟡",
    "high":     "🟠",
    "critical": "🔴",
}

CVSS_ICONS = {
    "LOW":      "🟢",
    "MEDIUM":   "🟡",
    "HIGH":     "🟠",
    "CRITICAL": "🔴",
    "UNKNOWN":  "⚪",
}


def _sev_icon(score: int) -> str:
    if score >= 80: return "🔴"
    if score >= 60: return "🟠"
    if score >= 30: return "🟡"
    return "🟢"


def _e(text: str) -> str:
    """Escape for Telegram MarkdownV2."""
    special = r"\_*[]()~`>#+-=|{}.!"
    return "".join(f"\\{c}" if c in special else c for c in str(text))


def _combined_summary(intel: dict) -> str:
    """Show only the technical summary — single clean paragraph."""
    tech_s = intel.get("technical_summary", "").strip()
    fallback = intel.get("executive_summary", "").strip()
    return _e(tech_s or fallback or "No summary available.")


def _is_high_impact(intel: dict) -> bool:
    sev = intel.get("severity", 0)
    cat = intel.get("category", "general")
    return sev >= 70 or cat in ("ransomware", "nation-state", "breach")


# ── CVE formatter ─────────────────────────────────────────────────────────────

def format_cve_message(
    cve_id: str,
    url: str,
    cvss_score: Optional[float],
    cvss_severity: str,
    intel: Dict[str, Any],
) -> str:
    sev       = intel.get("severity", 0)
    sev_icon  = _sev_icon(sev)
    cvss_icon = CVSS_ICONS.get(cvss_severity.upper(), "⚪")
    score_str = str(cvss_score) if cvss_score is not None else "N/A"
    exploit   = intel.get("exploitation_likelihood", "unknown")
    exp_icon  = EXPLOIT_ICONS.get(exploit.lower(), "⚪")
    rec       = intel.get("recommended_action", "")
    takeaway  = intel.get("key_takeaway", "")
    affected  = intel.get("affected_systems", [])

    # CVSS visual bar  ████████░░  (10 blocks)
    bar_filled = round((cvss_score or 0) / 10 * 10)
    bar = "█" * bar_filled + "░" * (10 - bar_filled)

    lines = [
        f"🛡️ *NEW VULNERABILITY ALERT*",
        f"",
        f"*{_e(cve_id)}*",
        f"",
        f"{cvss_icon} *CVSS {_e(score_str)}* \\({_e(cvss_severity)}\\)   {sev_icon} *AI Score: {sev}/100*",
        f"`{bar}`",
        f"{exp_icon} *Exploit Risk:* {_e(exploit.capitalize())}",
        f"",
        f"📋 *Summary*",
        _combined_summary(intel),
    ]

    if affected:
        lines += ["", f"💻 *Affected:* {_e(', '.join(affected[:4]))}"]

    if rec:
        lines += ["", f"⚡ *Action:* {_e(rec)}"]

    if takeaway:
        lines += ["", f"💡 {_e(takeaway)}"]

    lines += [
        "",
        f"🔗 [View on NVD]({url})",
        "",
        "━━━━━━━━━━━━━━━━━━━━",
        f"🤖 @HackerSnitchBot \\| \\#CVE \\#Vulnerability \\#CyberSnitch",
    ]

    return "\n".join(lines)


# ── Article formatter ─────────────────────────────────────────────────────────

def format_article_message(
    title: str,
    url: str,
    source: str,
    intel: Dict[str, Any],
) -> str:
    cat      = intel.get("category", "general")
    sev      = intel.get("severity", 0)
    cat_icon = CATEGORY_ICONS.get(cat, "📰")
    sev_icon = _sev_icon(sev)
    src_icon = SOURCE_ICONS.get(source, "📡")
    takeaway = intel.get("key_takeaway", "")
    actors   = intel.get("threat_actors", [])
    iocs     = intel.get("iocs", {})
    cves     = iocs.get("cves", [])
    domains  = iocs.get("domains", [])
    malware  = iocs.get("malware_names", [])

    if _is_high_impact(intel):
        return _format_high_impact(
            title, url, source, intel, cat, sev, cat_icon, sev_icon, src_icon,
            takeaway, actors, cves, domains, malware)
    else:
        return _format_intel_brief(
            title, url, source, intel, cat, sev, cat_icon, sev_icon, src_icon,
            takeaway, actors, cves, malware)


def _format_high_impact(title, url, source, intel, cat, sev, cat_icon,
                         sev_icon, src_icon, takeaway, actors, cves, domains, malware):
    """Bold alert layout for high-severity / ransomware / breach / nation-state."""
    lines = [
        f"⚠️ *HIGH\\-IMPACT ALERT*",
        f"",
        f"{cat_icon} *{_e(title)}*",
        f"",
        f"{sev_icon} *Severity:* {sev}/100   {src_icon} {_e(source)}",
        f"🏷️ *Category:* {_e(cat.upper())}",
        f"",
        f"📋 *Summary*",
        _combined_summary(intel),
    ]

    # IOC block
    ioc_lines = []
    if cves:    ioc_lines.append(f"CVEs: {_e(', '.join(cves[:4]))}")
    if domains: ioc_lines.append(f"Domains: {_e(', '.join(domains[:3]))}")
    if malware: ioc_lines.append(f"Malware: {_e(', '.join(malware[:3]))}")
    if actors:  ioc_lines.append(f"Actors: {_e(', '.join(actors[:3]))}")

    if ioc_lines:
        lines += ["", "🎯 *Threat Intel*"]
        lines += [f"• {l}" for l in ioc_lines]

    if takeaway:
        lines += ["", f"💡 *{_e(takeaway)}*"]

    lines += [
        "",
        f"🔗 [Read Full Article]({url})",
        "",
        "━━━━━━━━━━━━━━━━━━━━",
        f"🤖 @HackerSnitchBot \\| \\#{_e(cat.replace('-',''))} \\#CyberSnitch",
    ]
    return "\n".join(lines)


def _format_intel_brief(title, url, source, intel, cat, sev, cat_icon,
                         sev_icon, src_icon, takeaway, actors, cves, malware):
    """Compact layout for medium-priority intelligence."""
    lines = [
        f"{cat_icon} *{_e(title)}*",
        f"",
        f"{sev_icon} {sev}/100  {src_icon} {_e(source)}  🏷️ {_e(cat.capitalize())}",
        f"",
        f"📋 *Summary*",
        _combined_summary(intel),
    ]

    extras = []
    if cves:   extras.append(f"🔖 {_e(', '.join(cves[:3]))}")
    if malware:extras.append(f"🦠 {_e(', '.join(malware[:2]))}")
    if actors: extras.append(f"👤 {_e(', '.join(actors[:2]))}")
    if extras:
        lines += [""] + extras

    if takeaway:
        lines += ["", f"💡 _{_e(takeaway)}_"]

    lines += [
        "",
        f"🔗 [Read More]({url})",
        "",
        "━━━━━━━━━━━━━━━━━━━━",
        f"\\#Cybersecurity \\#ThreatIntelligence \\#CVE \\#InfoSec \\#CyberSnitch \\#{_e(cat.replace('-',''))}"
    ]
    return "\n".join(lines)
