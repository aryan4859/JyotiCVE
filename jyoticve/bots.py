"""Independent collection → normalization → analysis → outbox workflows."""
import json
from datetime import datetime, timedelta

from . import certificates, matching, sources
from .core import LOG, fingerprint, now, stamp


def severity(details, stack=False):
    score = details.get('cvss') or 0
    if details['kev'] or (stack and score >= 9):
        return 'critical'
    if score >= 7:
        return 'high'
    return 'medium' if stack else 'informational'


def start_time(state, config, key, end):
    cursor = state.get(key)
    return (datetime.fromisoformat(cursor) - timedelta(minutes=5)) if cursor else end - timedelta(hours=config.get('initial_lookback_hours', 24))


def cve_alert(bot, cve, kev, technologies):
    details = sources.normalize(cve, kev)
    if cve.get('vulnStatus') == 'Rejected':
        return None
    if bot == 'stack':
        matches = matching.match_cve(cve, technologies)
        if not matches:
            return None
        details['inventory_matches'] = matches
        confirmed = any(m['confidence'] == 'confirmed' for m in matches)
        priority = severity(details, True) if confirmed else 'informational'
        action = 'alert' if confirmed else 'review'
    else:
        priority = severity(details)
        action = 'alert' if priority in ('critical', 'high') else 'information'
    return {'title': f"{cve['id']} — {'technology stack' if bot == 'stack' else 'vulnerability intelligence'}",
            'severity': priority, 'kind': action,
            'summary': details['description'][:650], 'details': details}


def intel(bot, state, config, http):
    end = now()
    errors = []
    technologies = matching.inventory(config['inventory_file']) if bot == 'stack' else []
    cache_key = f'{bot}:kev'
    try:
        kev = sources.kev_catalog(http)
        state.put(cache_key, kev)
    except Exception as error:
        LOG.error('%s KEV collection failed (%s)', bot, type(error).__name__)
        # Do not overwrite known exploitation status with a false negative.
        # Do not advance NVD cursors until current KEV enrichment is available.
        return ['CISA KEV unavailable; CVE scan deferred, cursor retained'] + (news(state, config, http, end) if bot == 'news' else [])

    def accept(cve):
        alert = cve_alert(bot, cve, kev, technologies)
        state.put(f'cve:{bot}:{cve["id"]}', cve)
        if alert is None:
            prior = state.db.execute('SELECT payload FROM events WHERE bot=? AND identity=? ORDER BY id DESC LIMIT 1',
                                     (bot, cve['id'])).fetchone()
            previous_alert = json.loads(prior[0]) if prior else None
            if previous_alert and previous_alert.get('kind') != 'resolution':
                reason = ('NVD has rejected this CVE.' if cve.get('vulnStatus') == 'Rejected' else
                          'Current NVD criteria no longer match the configured inventory. Verify inventory and advisory changes; this does not prove remediation.')
                alert = {'title': f"{cve['id']} — finding status changed", 'severity': 'informational',
                         'kind': 'resolution', 'summary': reason, 'details': sources.normalize(cve, kev)}
        if alert:
            meaningful = json.loads(json.dumps(alert))
            meaningful['details'].pop('updated', None)  # Metadata-only timestamp edits do not re-alert.
            state.event(bot, cve['id'], alert, config['notifications'], meaningful)

    # Inventory changes need a product backfill, even if the CVE has not changed recently.
    if bot == 'stack' and state.get('stack:inventory') != fingerprint(technologies):
        try:
            for tech in technologies:
                identities = [(tech['vendor'], tech['product'])] + [tuple(a) for a in tech.get('aliases', [])]
                for vendor, product in identities:
                    for cve in sources.nvd_pages(http, virtualMatchString=f"cpe:2.3:{tech.get('part', 'a')}:{vendor}:{product}"):
                        accept(cve)
            cached_rows = state.db.execute("SELECT value FROM kv WHERE key LIKE 'cve:stack:%'").fetchall()
            for (raw,) in cached_rows:
                accept(json.loads(raw))
            state.put('stack:inventory', fingerprint(technologies))
        except Exception as error:
            errors.append(f'Inventory backfill incomplete ({type(error).__name__}); will retry')
    key = f'{bot}:nvd_cursor'
    try:
        for cve in sources.nvd_updates(http, start_time(state, config, key, end), end):
            accept(cve)
        state.put(key, end.isoformat())
    except Exception as error:
        errors.append(f'NVD scan incomplete ({type(error).__name__}); cursor retained')

    # New/changed KEV entries may refer to CVEs published many years ago.
    previous = state.get(f'{bot}:kev_processed', {})
    if bot == 'stack' and not previous and state.get('stack:inventory') == fingerprint(technologies):
        previous = {key: fingerprint(value) for key, value in kev.items()}
    completed = dict(previous)
    cutoff = start_time(state, config, f'{bot}:kev_cursor', end).date().isoformat()
    for cve_id, entry in kev.items():
        digest = fingerprint(entry)
        # First-run news only surfaces recent KEV additions; stack backfill covers older records.
        if not previous and bot == 'news' and entry.get('dateAdded', '') < cutoff:
            completed[cve_id] = digest
            continue
        if previous.get(cve_id) == digest:
            continue
        try:
            records = list(sources.nvd_pages(http, cveId=cve_id))
            if not records:
                if bot == 'news':
                    payload = {'title': f'{cve_id} — newly known exploited', 'severity': 'critical', 'kind': 'alert',
                               'summary': entry.get('shortDescription', ''), 'details': entry | {
                                   'cvss': None, 'exploitation': 'Confirmed exploited (CISA KEV)', 'kev': True,
                                   'remediation': entry.get('requiredAction'), 'references': [sources.KEV]}}
                    state.event(bot, cve_id, payload, config['notifications'])
                raise ValueError('NVD has no record yet; retry enrichment')
            for cve in records:
                accept(cve)
            completed[cve_id] = digest
        except Exception as error:
            errors.append(f'KEV enrichment incomplete for {cve_id} ({type(error).__name__})')
    # Re-evaluate cached CVEs when KEV entries are removed, too.
    for cve_id in previous.keys() - kev.keys():
        cached = state.get(f'cve:{bot}:{cve_id}')
        if cached:
            accept(cached)
        completed.pop(cve_id, None)
    state.put(f'{bot}:kev_processed', completed)
    state.put(f'{bot}:kev_cursor', end.isoformat())
    if bot == 'news':
        errors.extend(news(state, config, http, end))
    return errors


def news(state, config, http, end):
    key = 'news:hn_cursor'
    try:
        for item in sources.hacker_news(http, start_time(state, config, key, end), end,
                                        config.get('news_keywords', ['vulnerability', 'security breach', 'ransomware', 'zero-day'])):
            significant = any(term in item['title'].lower() for term in config.get('significant_news_terms',
                                                                                 ['actively exploited', 'zero-day', 'ransomware', 'breach']))
            payload = {'title': item['title'], 'severity': 'medium' if significant else 'informational',
                       'kind': 'alert' if significant else 'information',
                       'summary': 'Security news: ' + item['title'] + '. Review the source for impact; headline has not been independently verified.',
                       'details': item}
            state.event('news', item['id'], payload, config['notifications'])
        state.put(key, end.isoformat())
        return []
    except Exception as error:
        return [f'Hacker News scan incomplete ({type(error).__name__}); cursor retained']


def tls(state, config, http):
    results = []
    for host, port in certificates.domains(config['domains_file']):
        result = certificates.check(host, port, config['certificate_thresholds'],
                                    config.get('certificate_critical_days', 7), config.get('tls_timeout_seconds', 10))
        results.append(result)
        key = 'certificates:status:' + result['domain']
        previous = state.get(key)
        issue = certificates.issue_key(result)
        if result['status'] != 'valid' or (previous and previous['status'] != 'valid'):
            payload = {'title': f"TLS {result['domain']}: {result['status']}", 'severity': result['severity'],
                       'kind': 'recovery' if result['status'] == 'valid' else 'alert',
                       'summary': 'Certificate validation recovered.' if result['status'] == 'valid' else
                                  'Renew or replace the certificate, verify hostname and full chain, and investigate connection failures.',
                       'details': result}
            state.event('certificates', result['domain'], payload, config['notifications'], issue)
        # Include valid baseline transitions so a recurrence of the same error is delivered.
        elif previous != issue:
            state.put(f'event:certificates:{result["domain"]}', fingerprint(issue))
        state.put(key, issue)
    date = now().date().isoformat()
    payload = {'title': f'TLS daily summary — {date} UTC', 'severity': 'informational', 'kind': 'summary',
               'summary': f'{len(results)} domains checked; {sum(r["status"] != "valid" for r in results)} need attention.',
               'details': {'domains': results, 'inventory_empty': not results}}
    state.event('certificates', 'summary:' + date, payload, config['notifications'], meaningful={'date': date})
    return []


BOTS = {'news': lambda s, c, h: intel('news', s, c, h), 'certificates': tls,
        'stack': lambda s, c, h: intel('stack', s, c, h)}
