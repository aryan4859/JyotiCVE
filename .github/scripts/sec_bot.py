import os
import sys
import json
import re
import requests
import argparse

# --- Load Environment / Secrets ---
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

# --- 1. Parse Dependency Files in Repo ---
def parse_requirements(file_path):
    dependencies = {}
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                
                # Ignore empty lines, comments, and pip flags
                if not line or line.startswith("#") or line.startswith("-"):
                    continue
                
                # Extract package name and version using regex
                match = re.match(r"^([a-zA-Z0-9_\-\.]+)\s*([<>=!~]=?\s*.*)?$", line)
                if match:
                    package_name = match.group(1)
                    raw_version = match.group(2).strip() if match.group(2) else ""
                    # Strip specifiers like '==' or '>=' to extract raw version number
                    clean_version = re.sub(r"^[<>=!~]+", "", raw_version).strip()
                    
                    dependencies[package_name] = {
                        "version": clean_version,
                        "ecosystem": "PyPI"
                    }
                    
    except FileNotFoundError:
        print(f"Error: Specified file '{file_path}' was not found.")
        sys.exit(1)
        
    return dependencies

# --- 2. CISA Known Exploited Vulnerabilities (KEV) ---
def get_cisa_kev():
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        res = requests.get(url, timeout=10)
        if res.status_code == 200:
            return {item["cveID"]: item for item in res.json().get("vulnerabilities", [])}
    except Exception as e:
        print(f"CISA KEV Fetch Error: {e}")
    return {}

# --- 3. EPSS Score Fetching ---
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

# --- 4. HackerNews / Algolia Security News Filter ---
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

# --- 5. Dispatch Telegram Alert ---
def send_telegram_alert(title, details, news=[]):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print("Telegram credentials not configured. Skipping alert notification.")
        return

    message = f"🚨 *[CRITICAL] Security Correlation Alert*\n\n"
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

# --- 6. Execution Pipeline ---
def main():
    parser = argparse.ArgumentParser(description="Scan dependencies for vulnerabilities.")
    parser.add_argument("--file", default="requirements.txt", help="Path to dependency file")
    args = parser.parse_args()

    repo_packages = parse_requirements(args.file)
    if not repo_packages:
        print("No dependencies found in repository.")
        sys.exit(0)

    print(f"Successfully loaded {len(repo_packages)} packages from repository.")
    cisa_kev = get_cisa_kev()
    
    for pkg, info in repo_packages.items():
        osv_url = "https://api.osv.dev/v1/query"
        payload = {"package": {"name": pkg, "ecosystem": info["ecosystem"]}}
        if info["version"]:
            payload["version"] = info["version"]

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
                        hn_news = fetch_hackernews_alerts([pkg, cve_id])
                        
                        alert_details = {
                            "CVE ID": cve_id,
                            "Matched Package": f"`{pkg}@{info['version']}` ({info['ecosystem']})",
                            "CISA KEV Status": "⚠️ EXPLOITED IN WILD" if in_kev else "Clean",
                            "EPSS Exploitation Risk": f"{epss * 100:.2f}%",
                            "Summary": vuln.get("summary", "Critical dependency vulnerability detected.")[:200]
                        }
                        
                        send_telegram_alert(f"Dependency Threat: {pkg}", alert_details, news=hn_news)
        except Exception as e:
            print(f"Error querying OSV API for {pkg}: {e}")

if __name__ == "__main__":
    main()
