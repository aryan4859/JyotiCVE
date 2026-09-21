"""
Bot 3: Tech Stack CVE Alert Bot

Takes a declared list of the technologies/packages you actually run (with
ecosystem + version, e.g. Django 4.2.1 on PyPI, nginx 1.24.0 on Debian) and
checks each against OSV.dev for known vulnerabilities. Matches are enriched
with CISA KEV status and EPSS score, then alerted via Telegram.

Unlike passive fingerprinting (WhatWeb, etc.), this bot works off a stack
you maintain yourself in a JSON file, which gives OSV the ecosystem+version
context it needs for reliable matches instead of raw guesses from a scanner.

A small on-disk state file is used to avoid re-alerting on the same CVE
every run. For this to persist across scheduled runs, the workflow needs to
commit the state file back to the repo after each run (see the accompanying
workflow YAML).
"""
import os
import json
import time
import argparse

from alert_utils import SESSION, get_cisa_kev, get_epss_scores_bulk, send_telegram_alert

EPSS_ALERT_THRESHOLD = 0.10
DEFAULT_STACK_FILE = "tech_stack.json"
DEFAULT_STATE_FILE = "tech_stack_cve_state.json"


def load_tech_stack(path):
    """Expects a JSON file like:
    [
      {"name": "django", "ecosystem": "PyPI", "version": "4.2.1"},
      {"name": "nginx", "ecosystem": "Debian", "version": "1.24.0"}
    ]
    """
    if not os.path.exists(path):
        print(f"Tech stack file '{path}' not found.")
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            stack = json.load(f)
        return [s for s in stack if s.get("name") and s.get("ecosystem")]
    except (OSError, json.JSONDecodeError) as e:
        print(f"Error reading tech stack file '{path}': {e}")
        return []


def load_state(path):
    if not os.path.exists(path):
        return set()
    try:
        with open(path, "r", encoding="utf-8") as f:
            return set(json.load(f))
    except (OSError, json.JSONDecodeError) as e:
        print(f"Warning: could not read state file '{path}': {e}. Starting fresh.")
        return set()


def save_state(path, alerted_ids):
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(sorted(alerted_ids), f, indent=2)
    except OSError as e:
        print(f"Warning: could not write state file '{path}': {e}")


def query_osv(name, ecosystem, version):
    """Queries OSV.dev for known vulnerabilities affecting this exact package+version."""
    url = "https://api.osv.dev/v1/query"
    payload = {"package": {"name": name, "ecosystem": ecosystem}, "version": version}
    try:
        res = SESSION.post(url, json=payload, timeout=10)
        res.raise_for_status()
        return res.json().get("vulns", [])
    except Exception as e:
        print(f"Error querying OSV for {name}@{version} ({ecosystem}): {e}")
        return []


def process_tech_stack(stack_file, state_file):
    stack = load_tech_stack(stack_file)
    if not stack:
        print("No tech stack entries to check.")
        return

    print(f"Checking {len(stack)} tech stack entr(y/ies) against OSV...")
    cisa_kev = get_cisa_kev()
    alerted_ids = load_state(state_file)

    # First pass: collect every vuln hit across the whole stack
    findings = []  # list of (component_label, cve_id, summary)
    for entry in stack:
        name, ecosystem, version = entry["name"], entry["ecosystem"], entry.get("version", "")
        label = f"{name} {version} ({ecosystem})".strip()
        vulns = query_osv(name, ecosystem, version)

        for vuln in vulns:
            cve_id = next((a for a in vuln.get("aliases", []) if a.startswith("CVE-")), None)
            if not cve_id:
                continue
            findings.append((label, cve_id, vuln.get("summary", "No summary available.")))

    if not findings:
        print("No known vulnerabilities found for the declared tech stack.")
        return

    # Batch-fetch EPSS for every CVE found, once
    epss_scores = get_epss_scores_bulk(sorted({cve_id for _, cve_id, _ in findings}))

    new_alerts = 0
    for label, cve_id, summary in findings:
        # De-dupe per (component, CVE) pair, so the same CVE on two different
        # components still alerts once each, but repeat runs stay quiet.
        dedupe_key = f"{label}::{cve_id}"
        if dedupe_key in alerted_ids:
            continue

        epss = epss_scores.get(cve_id, 0.0)
        in_kev = cve_id in cisa_kev

        alert_details = {
            "Affected Component": label,
            "CVE ID": cve_id,
            "CISA KEV Status": "⚠️ EXPLOITED IN WILD" if in_kev else "Clean",
            "EPSS Exploitation Risk": f"{epss * 100:.2f}%",
            "Summary": summary[:300],
        }
        send_telegram_alert(
            f"Tech Stack Threat: {label}",
            alert_details,
            header="🧩 *[TECH STACK CVE ALERT]*"
        )
        alerted_ids.add(dedupe_key)
        new_alerts += 1
        time.sleep(0.5)

    save_state(state_file, alerted_ids)
    print(f"Found {len(findings)} total vuln match(es); sent {new_alerts} new alert(s).")


def main():
    parser = argparse.ArgumentParser(
        description="Alert on CVEs affecting a declared tech stack, via OSV + CISA KEV + EPSS."
    )
    parser.add_argument(
        "--stack-file", default=DEFAULT_STACK_FILE,
        help=f"Path to a JSON file listing your tech stack (default: {DEFAULT_STACK_FILE})"
    )
    parser.add_argument(
        "--state-file", default=DEFAULT_STATE_FILE,
        help=f"Path to a JSON file tracking already-alerted CVEs (default: {DEFAULT_STATE_FILE})"
    )
    args = parser.parse_args()

    process_tech_stack(args.stack_file, args.state_file)


if __name__ == "__main__":
    main()
