"""Query OSV for vulnerabilities affecting explicitly configured package versions."""
import argparse
import hashlib
import json
import time
from pathlib import Path

import requests
import sec_bot as common


def load_stack(path):
    entries = json.loads(Path(path).read_text())
    if not isinstance(entries, list):
        raise ValueError('tech_stack.json must be an array of package objects')
    stack = []
    for index, entry in enumerate(entries, 1):
        if not isinstance(entry, dict) or any(
                not isinstance(entry.get(key), str) or not entry[key].strip()
                for key in ('name', 'ecosystem', 'version')):
            raise ValueError(f'Package {index}: name, ecosystem and exact version must be nonempty strings')
        package = {key: entry[key].strip() for key in ('name', 'ecosystem', 'version')}
        if package not in stack:
            stack.append(package)
    return stack


def query_osv(package):
    payload = {'package': {'name': package['name'], 'ecosystem': package['ecosystem']},
               'version': package['version']}
    vulnerabilities = {}
    tokens = set()
    while True:
        data = None
        for attempt in range(3):
            try:
                response = common.SESSION.post('https://api.osv.dev/v1/query', json=payload, timeout=30)
                if response.status_code == 429 or response.status_code >= 500:
                    if attempt < 2:
                        time.sleep(min(float(response.headers.get('Retry-After', 2 ** attempt)), 60))
                        continue
                response.raise_for_status()
                candidate = response.json()
                if not isinstance(candidate, dict) or not isinstance(candidate.get('vulns', []), list):
                    raise ValueError('Invalid OSV response')
                data = candidate
                break
            except requests.HTTPError:
                # Invalid ecosystem/version queries must not be interpreted as no vulnerabilities.
                if response.status_code < 500 and response.status_code != 429:
                    break
            except (requests.RequestException, ValueError):
                pass
            if attempt < 2:
                time.sleep(2 ** attempt)
        if data is None:
            raise RuntimeError(f"OSV query failed for {package['ecosystem']}/{package['name']} {package['version']}; check ecosystem, package name and version")
        for vulnerability in data.get('vulns', []):
            if not isinstance(vulnerability, dict) or not vulnerability.get('id'):
                raise RuntimeError('OSV returned a malformed vulnerability')
            if not vulnerability.get('withdrawn'):
                vulnerabilities[vulnerability['id']] = vulnerability
        token = data.get('next_page_token')
        if not token:
            return list(vulnerabilities.values())
        if token in tokens:
            raise RuntimeError('OSV returned a repeated pagination token')
        tokens.add(token)
        payload['page_token'] = token


def identifiers(vulnerability):
    return sorted(set([vulnerability['id']] + vulnerability.get('aliases', [])))


class FindingHistory:
    """Keep delivered advisory IDs and CVE aliases per installed package/version."""
    def __init__(self, path):
        self.path = Path(path)
        try:
            data = json.loads(self.path.read_text())
            if not isinstance(data, list) or not all(isinstance(key, str) for key in data):
                raise ValueError('Invalid tech-stack delivery history')
            self.sent = set(data)
        except FileNotFoundError:
            self.sent = set()

    def keys(self, package, vulnerability):
        return {hashlib.sha256(json.dumps([package, alias], sort_keys=True).encode()).hexdigest()
                for alias in identifiers(vulnerability)}

    def save(self, keys):
        self.sent.update(keys)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix('.tmp')
        temporary.write_text(json.dumps(sorted(self.sent), indent=2) + '\n')
        temporary.replace(self.path)

    def deliver(self, package, vulnerability, details):
        keys = self.keys(package, vulnerability)
        if keys & self.sent:
            # Remember any newly assigned aliases without repeating the alert.
            self.save(keys)
            return 0
        if not common.send_telegram_alert(f"Tech-stack vulnerability: {package['name']} {package['version']}", details):
            return -1
        self.save(keys)
        return 1


def finding_details(package, vulnerability, kev, epss):
    cves = [value for value in identifiers(vulnerability) if value.startswith('CVE-')]
    fixed = set()
    for affected in vulnerability.get('affected', []):
        candidate = affected.get('package', {})
        if candidate.get('name') != package['name'] or candidate.get('ecosystem') != package['ecosystem']:
            continue
        for affected_range in affected.get('ranges', []):
            if affected_range.get('type') == 'GIT':
                continue
            for event in affected_range.get('events', []):
                if event.get('fixed'):
                    fixed.add(event['fixed'])
    return {
        'Package': f"{package['ecosystem']}/{package['name']} @ {package['version']}",
        'Advisory': vulnerability['id'], 'CVEs': ', '.join(cves) or 'No CVE assigned; OSV advisory only',
        'Summary': vulnerability.get('summary', 'See advisory details'),
        'Details': vulnerability.get('details', 'Not provided'),
        'Published': vulnerability.get('published', 'Unknown'),
        'Modified': vulnerability.get('modified', 'Unknown'),
        'CISA KEV': 'Source unavailable' if kev is None else (
            '\n'.join(f"{cve}: KNOWN EXPLOITED; {kev[cve].get('requiredAction', 'See CISA')}" for cve in cves if cve in kev)
            or ('Not listed (does not imply safe)' if cves else 'No CVE available for lookup')),
        'EPSS': '\n'.join(f"{cve}: {epss[cve] * 100:.2f}%" if cve in epss else f'{cve}: Not available' for cve in cves) or 'No CVE available for lookup',
        'Fix versions listed by advisory': ', '.join(sorted(fixed)) or 'Not provided; review advisory',
        'Upgrade guidance': 'Check the advisory for the fixed release on your supported branch.',
        'OSV record': f"https://osv.dev/vulnerability/{vulnerability['id']}",
        'References': '\n'.join(dict.fromkeys(ref['url'] for ref in vulnerability.get('references', []) if ref.get('url'))) or 'None provided',
    }


def run(stack, history, dry_run=False):
    common.SOURCE_ERRORS.clear()
    findings, failures = [], []
    for package in stack:
        try:
            findings.extend((package, vulnerability) for vulnerability in query_osv(package))
        except RuntimeError as error:
            failures.append(str(error))
    cves = sorted({value for _, vulnerability in findings for value in identifiers(vulnerability) if value.startswith('CVE-')})
    kev = common.get_cisa_kev() if cves else {}
    epss = common.get_epss_scores_bulk(cves)
    delivered = skipped = 0
    for package, vulnerability in findings:
        details = finding_details(package, vulnerability, kev, epss)
        if dry_run:
            print(json.dumps(details, indent=2))
            continue
        result = history.deliver(package, vulnerability, details)
        delivered += result == 1
        skipped += result == 0
        if result == -1:
            failures.append(f"Telegram delivery failed for {vulnerability['id']}")
    failures.extend(common.SOURCE_ERRORS)
    print(f'Checked {len(stack)} packages; {len(findings)} matching advisories; {delivered} delivered; {skipped} previously delivered.')
    if failures:
        if not dry_run:
            common.send_telegram_alert('Tech-stack bot incomplete', {'Errors': '\n'.join(failures)})
        raise RuntimeError('\n'.join(failures))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stack-file', default='tech_stack.json')
    parser.add_argument('--state-file', default='.tech-stack-state/tech_stack_cve_state.json')
    parser.add_argument('--dry-run', action='store_true', help='Query sources and print findings without sending or updating history')
    args = parser.parse_args()
    stack = load_stack(args.stack_file)
    if not stack:
        print('No packages configured. Add your installed package versions to tech_stack.json to enable monitoring.')
        return
    if not args.dry_run and not (common.TELEGRAM_BOT_TOKEN and common.TELEGRAM_CHAT_ID):
        parser.error('Set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID')
    run(stack, FindingHistory(args.state_file), args.dry_run)


if __name__ == '__main__':
    main()
