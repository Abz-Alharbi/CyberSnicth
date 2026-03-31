# HackerSnitch Pro v3 — Daily Digest 🛡️

One post per day. Instant alerts for critical CVEs. Zero noise.

## How It Works

```
Every 2 hours:
  → Fetch RSS feeds (4 sources)
  → Fetch NVD CVEs
  → Analyse with Groq AI
  → Store in inbox (silent — no posts)
  → IF CVSS >= 9.0 → send INSTANT ALERT immediately

Every day at 08:00:
  → Pick top 3 CVEs + top 5 news from inbox
  → Build one clean digest post
  → Send to channel
  → Clear inbox
```

## Quick Start

```bash
pip install -r requirements.txt
python bot.py
```

## File Structure

```
├── bot.py            ← Main loop + scheduler
├── collector.py      ← Silent RSS + CVE fetcher
├── digest_sender.py  ← Builds + sends daily digest
├── intel.py          ← Groq AI analysis
├── database.py       ← SQLite with inbox schema
├── config.py         ← All settings
├── requirements.txt
└── data/
    └── articles.db   ← Auto-created
```

## Configuration (config.py)

| Setting | Default | Description |
|---|---|---|
| `DIGEST_HOUR` | `8` | Hour to send daily digest (24h) |
| `DIGEST_MAX_NEWS` | `5` | Max news items per digest |
| `DIGEST_MAX_CVES` | `3` | Max CVE items per digest |
| `DIGEST_MIN_SEV` | `40` | Min AI severity score to enter inbox |
| `CRITICAL_CVE_THRESHOLD` | `9.0` | CVSS score for instant alert |
| `FETCH_INTERVAL_MINUTES` | `120` | Collection cycle (every 2 hours) |

## What Subscribers See

**Normal days:** One digest at 08:00 with up to 8 items.

**When a critical CVE drops:** An instant 🚨 alert, then still the normal digest at 08:00.

## Digest Format

```
🛡️ CyberSnitch Daily Intel
📅 Friday, February 28, 2025

8 curated threat intelligence items

━━━━━━━━━━━━━━━━━━━━

🔖 VULNERABILITY ALERTS

🟠 CVE-2025-1234 — CVSS 8.8 · Apache HTTP Server
Remote code execution via crafted request headers...
⚡ Apply patch CVE-2025-1234 from Apache advisory immediately
🔗 NVD Detail

━━━━━━━━━━━━━━━━━━━━

📡 THREAT INTELLIGENCE

🔒 LockBit Affiliate Targets Healthcare Sector
KrebsOnSecurity · 👤 LockBit
Three UK NHS trusts taken offline in coordinated ransomware...
💡 Isolate legacy Windows systems and verify backup integrity
🔗 Read More
```

## RSS Sources (reduced to highest signal)

- KrebsOnSecurity — unique investigative stories
- DarkReading — volume + quality balance  
- SecurityWeek — focused threat coverage
- UK NCSC — official government advisories
