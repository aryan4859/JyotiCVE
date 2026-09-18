import os
import json
import time
import argparse
from datetime import datetime, timedelta, timezone
import requests

# --- Load Environment / Secrets ---
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")
# Optional: an NVD API key raises the rate limit from 5 to 50 requests/30s.
# Free to request at https://nvd.nist.gov/developers/request-an-api-key
NVD_API_KEY = os.getenv("NVD_API_KEY")

# Reuse a single HTTP session for all outbound requests
SESSION = requests.Session()
SESSION.headers.update({"User-Agent": "sec-bot/1.0"})

# Alert thresholds
EPSS_ALERT_THRESHOLD = 0.10   # alert if >10% predicted exploitation probability
CVSS_ALERT_THRESHOLD = 9.0    # alert on CRITICAL severity regardless of EPSS/KEV


# --- 1. Passive Subdomain Discovery via crt.sh ---
def fetch_subdomains(domain, max_retries=3, backoff_seconds=5):
    """Fetches subdomains passively using Certificate Transparency logs (crt.sh).

    crt.sh is a free, community-run service that is prone to transient 502/503
    errors and timeouts under load. Retry a few times with backoff before
    giving up, since a single blip shouldn't blank out an entire scheduled run.
    """
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    subdomains = set()

    for attempt in range(1, max_retries + 1):
        try:
            res = SESSION.get(url, timeout=15)
            res.raise_for_status()
            entries = res.json()
            for entry in entries:
                name = entry.get("name_value", "")
                for sub in name.split("\n"):
                    sub = sub.strip().replace("*.", "")
                    if sub and domain in sub:
                        subdomains.add(sub)
            return sorted(subdomains)  # success - no need to retry

        except requests.exceptions.RequestException as e:
            print(f"crt.sh Query Error for {domain} (attempt {attempt}/{max_retries}): {e}")
        except (ValueError, json.JSONDecodeError) as e:
            print(f"crt.sh returned invalid JSON for {domain} (attempt {attempt}/{max_retries}): {e}")

        if attempt < max_retries:
            time.sleep(backoff_seconds * attempt)  # simple linear backoff: 5s, 10s, ...

    print(f"crt.sh remained unavailable for {domain} after {max_retries} attempts; giving up.")
    return sorted(subdomains)


# --- 2. Newly Published CVEs via NVD ---
def fetch_recent_nvd_cves(hours=6):
    """Fetches CVEs published in the last `hours` hours from the NVD 2.0 API."""
    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=hours)
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": 200,
    }
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}

    cves = []
    try:
        res = SESSION.get(url, params=params, headers=headers, timeout=30)
        res.raise_for_status()
        data = res.json()
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id")
            if not cve_id:
                continue

            descriptions = cve.get("descriptions", [])
            desc_text = next(
                (d.get("value", "") for d in descriptions if d.get("lang") == "en"),
                "No description available."
            )

            # Prefer the newest CVSS version available
            cvss_score = None
            metrics = cve.get("metrics", {})
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                metric_list = metrics.get(key)
                if metric_list:
                    cvss_score = metric_list[0].get("cvssData", {}).get("baseScore")
                    break

            cves.append({
                "id": cve_id,
                "description": desc_text.strip()[:300],
                "cvss": cvss_score,
            })

    except requests.exceptions.RequestException as e:
        print(f"NVD Fetch Error: {e}")
    except (ValueError, json.JSONDecodeError) as e:
        print(f"NVD returned invalid JSON: {e}")

    return cves


# --- 3. CISA Known Exploited Vulnerabilities (KEV) ---
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


# --- 4. EPSS Score Fetching (bulk) ---
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


# --- 5. HackerNews / Algolia Security News Filter ---
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


# --- 6. Dispatch Telegram Alert ---
def send_telegram_alert(title, details, news=None):
    news = news or []

    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print("Telegram credentials not configured. Skipping notification.")
        return

    message = "🚨 *[NEW CVE ALERT]*\n\n"
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
    except requests.exceptions.RequestException as e:
        print(f"Failed to send Telegram alert: {e}")


# --- 7. Correlate New CVEs Against KEV / EPSS and Alert ---
def process_new_cves(hours):
    print(f"Checking NVD for CVEs published in the last {hours} hour(s)...")
    cisa_kev = get_cisa_kev()
    new_cves = fetch_recent_nvd_cves(hours)
    print(f"Found {len(new_cves)} newly published CVE(s).")

    if not new_cves:
        return

    cve_ids = [c["id"] for c in new_cves]
    epss_scores = get_epss_scores_bulk(cve_ids)

    alert_count = 0
    for cve in new_cves:
        cve_id = cve["id"]
        cvss = cve.get("cvss")
        epss = epss_scores.get(cve_id, 0.0)
        in_kev = cve_id in cisa_kev
        is_critical = cvss is not None and cvss >= CVSS_ALERT_THRESHOLD

        if not (in_kev or epss > EPSS_ALERT_THRESHOLD or is_critical):
            continue

        hn_news = fetch_hackernews_alerts([cve_id])
        alert_details = {
            "CVSS Score": f"{cvss}" if cvss is not None else "N/A",
            "CISA KEV Status": "⚠️ EXPLOITED IN WILD" if in_kev else "Clean",
            "EPSS Exploitation Risk": f"{epss * 100:.2f}%",
            "Summary": cve.get("description", "No description available."),
        }
        send_telegram_alert(cve_id, alert_details, news=hn_news)
        alert_count += 1
        time.sleep(0.5)  # be polite to Telegram/HN when many alerts fire in a row

    print(f"Sent {alert_count} alert(s) out of {len(new_cves)} new CVE(s).")


# --- 8. Execution Pipeline ---
def main():
    parser = argparse.ArgumentParser(
        description="Monitor for newly published high-risk CVEs (NVD + CISA KEV + EPSS + HackerNews), "
                    "with optional passive subdomain discovery."
    )
    parser.add_argument("--domain", help="Base domain to query crt.sh for subdomains (e.g., example.com)")
    parser.add_argument(
        "--hours", type=float, default=6,
        help="Look back this many hours for newly published CVEs (default: 6, matching a 6-hour schedule)"
    )
    args = parser.parse_args()

    # Optional: subdomain discovery
    if args.domain:
        print(f"Fetching subdomains for {args.domain} via crt.sh...")
        subdomains = fetch_subdomains(args.domain)
        print(f"Found {len(subdomains)} subdomains.")
        for sub in subdomains:
            print(f" - {sub}")

    # New CVE alerting
    process_new_cves(args.hours)


if __name__ == "__main__":
    main()
