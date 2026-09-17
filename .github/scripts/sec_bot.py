import os
import sys
import json
import re
import requests
import argparse

# --- Load Environment / Secrets ---
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

# --- 1. Passive Subdomain Discovery via crt.sh ---
def fetch_subdomains(domain):
    """Fetches subdomains passively using Certificate Transparency logs (crt.sh)."""
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    subdomains = set()
    try:
        res = requests.get(url, timeout=15)
        if res.status_code == 200:
            entries = res.json()
            for entry in entries:
                name = entry.get("name_value", "")
                # Handle multi-line results or wildcard entries
                for sub in name.split("\n"):
                    sub = sub.strip().replace("*.", "")
                    if sub and domain in sub:
                        subdomains.add(sub)
    except Exception as e:
        print(f"crt.sh Query Error for {domain}: {e}")
    return sorted(list(subdomains))

# --- 2. Load Technology Stack Results ---
def parse_whatweb_json(json_file):
    """Parses a WhatWeb JSON output file to identify running packages/technologies."""
    tech_map = {}
    if not os.path.exists(json_file):
        print(f"Warning: WhatWeb log file '{json_file}' not found.")
        return tech_map

    try:
        with open(json_file, "r", encoding="utf-8") as f:
            data = json.load(f)
            for entry in data:
                target = entry.get("target", "Unknown Target")
                plugins = entry.get("plugins", {})
                tech_map[target] = []
                
                for plugin_name, plugin_info in plugins.items():
                    version = plugin_info.get("version", [])
                    version_str = version[0] if version else ""
                    tech_map[target].append({
                        "name": plugin_name,
                        "version": version_str
                    })
    except Exception as e:
        print(f"Error reading WhatWeb JSON: {e}")
    return tech_map

# --- 3. CISA Known Exploited Vulnerabilities (KEV) ---
def get_cisa_kev():
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        res = requests.get(url, timeout=10)
        if res.status_code == 200:
            return {item["cveID"]: item for item in res.json().get("vulnerabilities", [])}
    except Exception as e:
        print(f"CISA KEV Fetch Error: {e}")
    return {}

# --- 4. EPSS Score Fetching ---
def get_epss_score(cve_id):
    url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
    try:
        res = requests.get(url, timeout=10)
        if res.status_code == 200:
            data = res.json().get("data", [])
            if data:
                return float(data[0].get("epss", 0.0))
    except Exception as e:
        print(f"EPSS Fetch Error: {e}")
    return 0.0

# --- 5. HackerNews / Algolia Security News Filter ---
def fetch_hackernews_alerts(keywords):
    query = " OR ".join(keywords)
    url = f"https://hn.algolia.com/api/v1/search_by_date?query={query}&tags=story"
    news_items = []
    try:
        res = requests.get(url, timeout=10)
        if res.status_code == 200:
            hits = res.json().get("hits", [])[:3]
            for hit in hits:
                news_items.append({
                    "title": hit.get("title"),
                    "url": hit.get("url") or f"https://news.ycombinator.com/item?id={hit.get('objectID')}"
                })
    except Exception as e:
        print(f"HackerNews Fetch Error: {e}")
    return news_items

# --- 6. Dispatch Telegram Alert ---
def send_telegram_alert(title, details, news=[]):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print("Telegram credentials not configured. Skipping notification.")
        return

    message = f"🚨 *[SECURITY ALERT] Target Analysis*\n\n"
    message += f"📌 *Target:* {title}\n"
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
        requests.post(url, json=payload, timeout=10)
    except Exception as e:
        print(f"Failed to send Telegram alert: {e}")

# --- 7. Execution Pipeline ---
def main():
    parser = argparse.ArgumentParser(description="Scan domain subdomains and technologies for security risks.")
    parser.add_argument("--domain", help="Base domain to query crt.sh (e.g., example.com)")
    parser.add_argument("--whatweb-file", help="Path to WhatWeb JSON log file")
    args = parser.parse_args()

    cisa_kev = get_cisa_kev()

    # 1. Subdomain Discovery
    if args.domain:
        print(f"Fetching subdomains for {args.domain} via crt.sh...")
        subdomains = fetch_subdomains(args.domain)
        print(f"Found {len(subdomains)} subdomains.")
        for sub in subdomains:
            print(f" - {sub}")

    # 2. Technology & Vulnerability Analysis
    if args.whatweb_file:
        tech_map = parse_whatweb_json(args.whatweb_file)
        for target, tech_list in tech_map.items():
            for tech in tech_list:
                pkg_name = tech["name"]
                pkg_ver = tech["version"]

                osv_url = "https://api.osv.dev/v1/query"
                payload = {"package": {"name": pkg_name}}
                if pkg_ver:
                    payload["version"] = pkg_ver

                try:
                    res = requests.post(osv_url, json=payload, timeout=10)
                    if res.status_code == 200 and "vulns" in res.json():
                        for vuln in res.json()["vulns"]:
                            cve_id = next((alias for alias in vuln.get("aliases", []) if alias.startswith("CVE-")), None)
                            if not cve_id:
                                continue

                            epss = get_epss_score(cve_id)
                            in_kev = cve_id in cisa_kev

                            if in_kev or epss > 0.10:
                                hn_news = fetch_hackernews_alerts([pkg_name, cve_id])
                                alert_details = {
                                    "CVE ID": cve_id,
                                    "Matched Tech": f"`{pkg_name}` ({pkg_ver if pkg_ver else 'Unknown Version'})",
                                    "CISA KEV Status": "⚠️ EXPLOITED IN WILD" if in_kev else "Clean",
                                    "EPSS Exploitation Risk": f"{epss * 100:.2f}%",
                                    "Summary": vuln.get("summary", "Security vulnerability detected.")[:200]
                                }
                                send_telegram_alert(f"Asset Threat: {target}", alert_details, news=hn_news)
                except Exception as e:
                    print(f"Error querying OSV API for {pkg_name}: {e}")

if __name__ == "__main__":
    main()
