"""
Shared helpers used by all three security bots:
  - cve_news_bot.py         (new CVE feed: NVD + CISA KEV + EPSS + HackerNews)
  - cert_expiry_bot.py       (TLS certificate expiry checks)
  - tech_stack_cve_bot.py    (CVEs affecting your declared tech stack)

Keeping this in one place means Telegram formatting, KEV/EPSS lookups, and
HTTP session handling only need to be fixed in one spot.
"""
import os
import json
import requests

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

# Reuse a single HTTP session for all outbound requests across bots
SESSION = requests.Session()
SESSION.headers.update({"User-Agent": "sec-bot/1.0"})


# --- CISA Known Exploited Vulnerabilities (KEV) ---
def get_cisa_kev():
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        res = SESSION.get(url, timeout=10)
        res.raise_for_status()
        return {item["cveID"]: item for item in res.json().get("vulnerabilities", [])}
    except requests.exceptions.RequestException as e:
        print(f"CISA KEV Fetch Error: {e}")
    except (ValueError, json.JSONDecodeError) as e:
        print(f"CISA KEV returned invalid JSON: {e}")
    return {}


# --- EPSS Score Fetching (bulk) ---
def get_epss_scores_bulk(cve_ids, batch_size=100):
    """Fetches EPSS scores for many CVEs at once, in batches, to minimize requests."""
    scores = {}
    if not cve_ids:
        return scores

    url = "https://api.first.org/data/v1/epss"
    for i in range(0, len(cve_ids), batch_size):
        batch = cve_ids[i:i + batch_size]
        try:
            res = SESSION.get(url, params={"cve": ",".join(batch)}, timeout=15)
            res.raise_for_status()
            for item in res.json().get("data", []):
                cve_id = item.get("cve")
                try:
                    scores[cve_id] = float(item.get("epss", 0.0))
                except (TypeError, ValueError):
                    scores[cve_id] = 0.0
        except requests.exceptions.RequestException as e:
            print(f"EPSS Fetch Error: {e}")
        except (ValueError, json.JSONDecodeError) as e:
            print(f"EPSS returned invalid JSON: {e}")

    return scores


# --- HackerNews / Algolia Security News Filter ---
def fetch_hackernews_alerts(keywords):
    query = " OR ".join(keywords)
    url = "https://hn.algolia.com/api/v1/search_by_date"
    news_items = []
    try:
        res = SESSION.get(url, params={"query": query, "tags": "story"}, timeout=10)
        res.raise_for_status()
        hits = res.json().get("hits", [])[:3]
        for hit in hits:
            news_items.append({
                "title": hit.get("title"),
                "url": hit.get("url") or f"https://news.ycombinator.com/item?id={hit.get('objectID')}"
            })
    except requests.exceptions.RequestException as e:
        print(f"HackerNews Fetch Error: {e}")
    except (ValueError, json.JSONDecodeError) as e:
        print(f"HackerNews returned invalid JSON: {e}")
    return news_items


# --- Dispatch Telegram Alert ---
def send_telegram_alert(title, details, news=None, header="🚨 *[SECURITY ALERT]*"):
    news = news or []

    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print("Telegram credentials not configured. Skipping notification.")
        return False

    message = f"{header}\n\n"
    message += f"📌 *{title}*\n"
    for key, val in details.items():
        message += f"• *{key}:* {val}\n"

    if news:
        message += "\n📰 *Related Security News (HackerNews):*\n"
        for item in news:
            message += f"• [{item['title']}]({item['url']})\n"

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": "Markdown",
        "disable_web_page_preview": True
    }
    try:
        res = SESSION.post(url, json=payload, timeout=10)
        res.raise_for_status()
        return True
    except requests.exceptions.RequestException as e:
        print(f"Failed to send Telegram alert: {e}")
        return False
