"""
Bot 1: New CVE / Security News Alert Bot

Pulls newly published CVEs from NVD, cross-references each against CISA's
Known Exploited Vulnerabilities (KEV) list and its EPSS exploitation-probability
score, and alerts via Telegram on anything that's actively exploited, high
probability of exploitation, or CRITICAL severity. Attaches related
HackerNews coverage when available.

This bot is domain/tech-stack agnostic - it's a general "what's new and
dangerous in the CVE world" feed. For CVEs specific to your own tech stack,
see tech_stack_cve_bot.py instead.
"""
import time
import argparse
from datetime import datetime, timedelta, timezone

from alert_utils import (
    SESSION, get_cisa_kev, get_epss_scores_bulk,
    fetch_hackernews_alerts, send_telegram_alert,
)

# Alert thresholds
EPSS_ALERT_THRESHOLD = 0.10   # alert if >10% predicted exploitation probability
CVSS_ALERT_THRESHOLD = 9.0    # alert on CRITICAL severity regardless of EPSS/KEV


def fetch_recent_nvd_cves(hours=6, nvd_api_key=None):
    """Fetches CVEs published in the last `hours` hours from the NVD 2.0 API."""
    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=hours)
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": 200,
    }
    headers = {"apiKey": nvd_api_key} if nvd_api_key else {}

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

    except Exception as e:
        print(f"NVD Fetch Error: {e}")

    return cves


def process_new_cves(hours, nvd_api_key=None):
    print(f"Checking NVD for CVEs published in the last {hours} hour(s)...")
    cisa_kev = get_cisa_kev()
    new_cves = fetch_recent_nvd_cves(hours, nvd_api_key=nvd_api_key)
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
        send_telegram_alert(cve_id, alert_details, news=hn_news, header="🚨 *[NEW CVE ALERT]*")
        alert_count += 1
        time.sleep(0.5)

    print(f"Sent {alert_count} alert(s) out of {len(new_cves)} new CVE(s).")


def main():
    parser = argparse.ArgumentParser(
        description="Alert on newly published high-risk CVEs (NVD + CISA KEV + EPSS + HackerNews)."
    )
    parser.add_argument(
        "--hours", type=float, default=6,
        help="Look back this many hours for newly published CVEs (default: 6, matching a 6-hour schedule)"
    )
    parser.add_argument(
        "--nvd-api-key", default=None,
        help="Optional NVD API key (raises the rate limit from 5 to 50 requests/30s). "
             "Can also be set via the NVD_API_KEY environment variable."
    )
    args = parser.parse_args()

    import os
    nvd_api_key = args.nvd_api_key or os.getenv("NVD_API_KEY")

    process_new_cves(args.hours, nvd_api_key=nvd_api_key)


if __name__ == "__main__":
    main()
