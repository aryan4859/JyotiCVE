import os
import json
import re
import requests

# --- Load Environment / Secrets ---
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

# --- 1. Parse Dependency Files in Repo ---
def parse_dependencies():
    """Extracts package names and versions from requirements.txt or package.json."""
    dependencies = {}

    # Check requirements.txt
    if os.path.exists("requirements.txt"):
        with open("requirements.txt", "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                match = re.match(r"^([a-zA-Z0-9_\-]+)\s*(?:==|>=|~=)?\s*([0-9\.]+)?", line)
                if match:
                    pkg = match.group(1).lower()
                    version = match.group(2) if match.group(2) else "0.0.0"
                    dependencies[pkg] = {"version": version, "ecosystem": "PyPI"}

    # Check package.json
    if os.path.exists("package.json"):
        with open("package.json", "r") as f:
            data = json.load(f)
            deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
            for pkg, ver in deps.items():
                clean_ver = re.sub(r"[^0-9\.]", "", ver)
                dependencies[pkg.lower()] = {"version": clean_ver or "0.0.0", "ecosystem": "npm"}

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
    requests.post(url, json=payload)

# --- 6. Execution Pipeline ---
def main():
    repo_packages = parse_dependencies()
    if not repo_packages:
        print("No dependencies found in repository.")
        return

    print(f"Successfully loaded {len(repo_packages)} packages from repository.")
    cisa_kev = get_cisa_kev()
    
    for pkg, info in repo_packages.items():
        osv_url = "https://api.osv.dev/v1/query"
        payload = {"package": {"name": pkg, "ecosystem": info["ecosystem"]}, "version": info["version"]}
        
        res = requests.post(osv_url, json=payload)
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

if __name__ == "__main__":
    main()
