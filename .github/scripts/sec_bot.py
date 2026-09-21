import os
import json
import time
import argparse
import hashlib
import html
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from email.utils import parsedate_to_datetime
from datetime import datetime, timedelta, timezone
import requests

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")
NVD_API_KEY = os.getenv("NVD_API_KEY")
SESSION = requests.Session()
SESSION.headers.update({"User-Agent": "sec-bot/2.0"})
EPSS_ALERT_THRESHOLD = 0.10
CVSS_ALERT_THRESHOLD = 9.0
SOURCE_ERRORS = []


def source_error(source, reason):
    message = f"{source}: {reason}"
    SOURCE_ERRORS.append(message)
    print(message)


def get_json(source, url, **kwargs):
    """Retry temporary failures; keep unavailable sources distinct from empty results."""
    for attempt in range(3):
        try:
            response = SESSION.get(url, timeout=30, **kwargs)
            if response.status_code == 429 or response.status_code >= 500:
                if attempt < 2:
                    time.sleep(min(float(response.headers.get("Retry-After", 6 * (attempt + 1))), 60))
                    continue
            response.raise_for_status()
            data = response.json()
            if not isinstance(data, dict):
                raise ValueError("Expected a JSON object")
            return data
        except (requests.RequestException, ValueError):
            if attempt < 2:
                time.sleep(6 * (attempt + 1))
    source_error(source, "unavailable after 3 attempts; results may be incomplete")
    return None


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


def fetch_recent_nvd_cves(hours=6):
    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=hours)
    params = {
        "pubStartDate": start.isoformat(timespec="milliseconds"),
        "pubEndDate": end.isoformat(timespec="milliseconds"),
        "resultsPerPage": 2000,
        "startIndex": 0,
    }
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    cves = {}
    while True:
        data = get_json("NVD", "https://services.nvd.nist.gov/rest/json/cves/2.0",
                        params=params, headers=headers)
        if data is None:
            break
        items = data.get("vulnerabilities", [])
        for item in items:
            cve = item.get("cve", {})
            if not cve.get("id"):
                continue
            score = severity = vector = version = None
            for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                metrics = cve.get("metrics", {}).get(key, [])
                if metrics:
                    metric = next((m for m in metrics if m.get("type") == "Primary"), metrics[0])
                    cvss = metric.get("cvssData", {})
                    score = cvss.get("baseScore")
                    severity = cvss.get("baseSeverity") or metric.get("baseSeverity")
                    vector, version = cvss.get("vectorString"), cvss.get("version")
                    if score is not None:
                        break
            cves[cve["id"]] = {
                "id": cve["id"],
                "description": next((d["value"] for d in cve.get("descriptions", [])
                                     if d.get("lang") == "en"), "No English description available."),
                "cvss": score, "severity": severity, "vector": vector, "version": version,
                "published": cve.get("published", "Unknown"),
                "modified": cve.get("lastModified", "Unknown"),
                "status": cve.get("vulnStatus", "Unknown"),
                "references": list(dict.fromkeys(r["url"] for r in cve.get("references", []) if r.get("url"))),
            }
        params["startIndex"] += len(items)
        if params["startIndex"] >= data.get("totalResults", 0):
            break
        if not items:
            source_error("NVD", "pagination stopped before all results were returned")
            break
        time.sleep(0.7 if NVD_API_KEY else 6)
    return list(cves.values())


def get_cisa_kev():
    data = get_json("CISA KEV", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
    return None if data is None else {item["cveID"]: item for item in data.get("vulnerabilities", [])}


def get_epss_scores_bulk(cve_ids, batch_size=100):
    scores = {}
    for i in range(0, len(cve_ids), batch_size):
        data = get_json("EPSS", "https://api.first.org/data/v1/epss",
                        params={"cve": ",".join(cve_ids[i:i + batch_size]), "limit": batch_size})
        for item in (data or {}).get("data", []):
            try:
                scores[item["cve"]] = float(item["epss"])
            except (KeyError, TypeError, ValueError):
                continue
    return scores


def fetch_hackernews_alerts(keywords, hours=6):
    cutoff = int((datetime.now(timezone.utc) - timedelta(hours=hours)).timestamp())
    news = {}
    for keyword in keywords:
        page = 0
        while True:
            data = get_json("Hacker News", "https://hn.algolia.com/api/v1/search_by_date",
                            params={"query": keyword, "tags": "story", "page": page,
                                    "hitsPerPage": 100, "numericFilters": f"created_at_i>{cutoff}"})
            if data is None:
                break
            for hit in data.get("hits", []):
                url = hit.get("url") or f"https://news.ycombinator.com/item?id={hit.get('objectID')}"
                news[url] = {"title": hit.get("title") or "Untitled story", "url": url,
                             "source": "Hacker News (Y Combinator)"}
            page += 1
            if page >= data.get("nbPages", 0):
                break
    return list(news.values())


def fetch_the_hacker_news(hours=6):
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    try:
        response = SESSION.get("https://feeds.feedburner.com/TheHackersNews", timeout=30)
        response.raise_for_status()
        root = ET.fromstring(response.content)
        news = []
        for item in root.findall("./channel/item"):
            published = parsedate_to_datetime(item.findtext("pubDate", ""))
            if published < cutoff:
                continue
            news.append({"title": item.findtext("title", "Untitled story"),
                         "url": item.findtext("link", ""), "source": "The Hacker News",
                         "summary": html.unescape(re.sub(r"<[^>]+>", "", item.findtext("description", "")))})
        return news
    except (requests.RequestException, ET.ParseError, ValueError, TypeError):
        source_error("The Hacker News", "feed unavailable or invalid; news may be incomplete")
        return []


def split_telegram_message(message, limit=3900):
    """Preserve every character; count UTF-16 units conservatively for emoji."""
    chunk, units = [], 0
    for char in message:
        size = len(char.encode("utf-16-le")) // 2
        if units + size > limit:
            yield "".join(chunk)
            chunk, units = [], 0
        chunk.append(char)
        units += size
    if chunk:
        yield "".join(chunk)


def send_telegram_alert(title, details, news=None):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        raise RuntimeError("TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID must be configured")
    message = f"🛡️ {title}\n\n"
    message += "\n".join(f"{key}: {value}" for key, value in details.items())
    if news:
        message += "\n\nRelated security news:\n" + "\n".join(f"{n['title']}\n{n['url']}" for n in news)
    # Plain text avoids interpreting untrusted descriptions/URLs as Markdown.
    for chunk in split_telegram_message(message):
        for attempt in range(3):
            try:
                response = SESSION.post(
                    f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
                    json={"chat_id": TELEGRAM_CHAT_ID, "text": chunk, "disable_web_page_preview": True},
                    timeout=30)
                data = response.json()
                if response.status_code == 429 or data.get("error_code") == 429:
                    if attempt < 2:
                        time.sleep(min(float(data.get("parameters", {}).get("retry_after", 5)), 60))
                        continue
                if response.status_code >= 500 and attempt < 2:
                    time.sleep(2 ** attempt)
                    continue
                if not response.ok or not data.get("ok"):
                    print(f"Telegram rejected message (code {data.get('error_code', response.status_code)})")
                    return False
                break
            except (requests.RequestException, ValueError):
                # Do not log exception URLs, which contain the bot token.
                print("Telegram delivery failed; this item will be retried on the next run")
                return False
        time.sleep(1.1)
    return True


class DeliveryState:
    def __init__(self, path):
        self.path = Path(path)
        try:
            self.sent = json.loads(self.path.read_text())
            if not isinstance(self.sent, dict):
                raise ValueError("State must be an object")
        except FileNotFoundError:
            self.sent = {}
        # Retain a week of successful delivery fingerprints.
        cutoff = time.time() - 7 * 86400
        self.sent = {key: value for key, value in self.sent.items() if value >= cutoff}

    def deliver(self, title, details):
        fingerprint = hashlib.sha256(json.dumps([title, details], sort_keys=True).encode()).hexdigest()
        if fingerprint in self.sent:
            return 0
        if not send_telegram_alert(title, details):
            return -1
        self.sent[fingerprint] = time.time()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(json.dumps(self.sent))
        temporary.replace(self.path)
        return 1


def process_new_cves(hours, state=None, high_risk_only=False, news_source="both"):
    SOURCE_ERRORS.clear()
    state = state or DeliveryState(".bot-state/sent.json")
    kev = get_cisa_kev()
    cves = fetch_recent_nvd_cves(hours)
    epss_scores = get_epss_scores_bulk([c["id"] for c in cves])
    sent = failed = filtered = 0

    def deliver(title, details):
        nonlocal sent, failed
        result = state.deliver(title, details)
        sent += result == 1
        failed += result == -1

    for cve in cves:
        cve_id = cve["id"]
        entry = (kev or {}).get(cve_id)
        epss = epss_scores.get(cve_id)
        risk = entry is not None or (epss is not None and epss > EPSS_ALERT_THRESHOLD) or (cve["cvss"] is not None and cve["cvss"] >= CVSS_ALERT_THRESHOLD)
        if high_risk_only and not risk:
            filtered += 1
            continue
        details = {
            "CVSS": f"{cve['cvss']} ({cve['severity'] or 'severity unavailable'}, v{cve['version']})" if cve["cvss"] is not None else "Not yet available",
            "CVSS vector": cve["vector"] or "Not yet available",
            "CISA KEV": "Source unavailable" if kev is None else "Known exploited vulnerability" if entry else "Not listed (does not imply safe)",
            "EPSS": f"{epss * 100:.2f}%" if epss is not None else "Not yet available",
            "Published (UTC)": cve["published"], "Last modified (UTC)": cve["modified"],
            "NVD status": cve["status"], "Description": cve["description"],
            "NVD record": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "References": "\n".join(cve["references"]) or "None provided",
        }
        if entry:
            details.update({"Required action": entry.get("requiredAction", "See CISA"), "CISA due date": entry.get("dueDate", "Not provided")})
        deliver(f"{'HIGH-RISK ' if risk else ''}CVE: {cve_id}", details)

    # Recent KEV additions can refer to CVEs published years ago.
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).date().isoformat()
    for cve_id, entry in (kev or {}).items():
        if entry.get("dateAdded", "") >= cutoff:
            deliver(f"CISA KEV addition: {cve_id}", {
                "Vulnerability": entry.get("vulnerabilityName", cve_id),
                "Vendor / product": f"{entry.get('vendorProject', 'Unknown')} / {entry.get('product', 'Unknown')}",
                "Description": entry.get("shortDescription", "Not provided"),
                "Date added": entry.get("dateAdded"), "Required action": entry.get("requiredAction", "Not provided"),
                "Due date": entry.get("dueDate", "Not provided"),
                "Ransomware use": entry.get("knownRansomwareCampaignUse", "Unknown"),
                "Notes": entry.get("notes", ""), "NVD record": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            })
    news = []
    if news_source in ("hn", "both"):
        news += fetch_hackernews_alerts(["cybersecurity", "vulnerability", "ransomware", "CVE"], hours)
    if news_source in ("thn", "both"):
        news += fetch_the_hacker_news(hours)
    for item in news:
        deliver(f"Security news: {item['title']}", {"Source": item["source"], "Summary": item.get("summary") or "Open the source link for the article.", "Link": item["url"]})
    if SOURCE_ERRORS:
        if not send_telegram_alert("Bot data-source warning", {"Incomplete sources": "\n".join(SOURCE_ERRORS)}):
            failed += 1
    print(f"Fetched {len(cves)} CVEs and {len(news)} news items; sent {sent}, filtered {filtered}, failed {failed}. Previously delivered items skipped.")
    if failed or SOURCE_ERRORS:
        raise RuntimeError("Run incomplete; check source/delivery warnings above")


def main():
    parser = argparse.ArgumentParser(description="Cybersecurity news and CVE alerts with full Telegram details")
    parser.add_argument("--domain", help="Optional passive crt.sh subdomain lookup")
    parser.add_argument("--hours", type=float, default=6, help="Overlapping lookback window (default: 6 hours)")
    parser.add_argument("--high-risk-only", action="store_true", help="Restrict NVD alerts to KEV, EPSS >10%% or CVSS >=9")
    parser.add_argument("--news-source", choices=("hn", "thn", "both", "none"), default="both")
    parser.add_argument("--state-file", default=".bot-state/sent.json")
    args = parser.parse_args()
    if not 0 < args.hours <= 120 * 24:
        parser.error("--hours must be greater than zero and at most 2880 (120 days)")
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        parser.error("Set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID")
    if args.domain:
        for subdomain in fetch_subdomains(args.domain):
            print(subdomain)
    process_new_cves(args.hours, DeliveryState(args.state_file), args.high_risk_only, args.news_source)


if __name__ == "__main__":
    main()
