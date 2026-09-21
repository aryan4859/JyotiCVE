"""Source adapters. Exceptions prevent cursor advancement on incomplete downloads."""
import os
from datetime import timedelta

NVD = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
KEV = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
HN = 'https://hn.algolia.com/api/v1/search_by_date'


def nvd_pages(http, **params):
    offset = 0
    while True:
        data = http.get(NVD, params=params | {'startIndex': offset, 'resultsPerPage': 2000},
                        headers={'apiKey': os.environ['NVD_API_KEY']} if os.getenv('NVD_API_KEY') else {})
        items, total = data['vulnerabilities'], data['totalResults']
        if not isinstance(items, list) or type(total) is not int:
            raise ValueError('Malformed NVD page')
        for item in items:
            cve = item['cve']
            if not isinstance(cve.get('id'), str):
                raise ValueError('Malformed NVD CVE')
            yield cve
        offset += len(items)
        if offset >= total:
            return
        if not items:
            raise ValueError('Incomplete NVD pagination')


def nvd_updates(http, start, end):
    while start < end:
        stop = min(end, start + timedelta(days=119))
        yield from nvd_pages(http, lastModStartDate=start.isoformat(timespec='milliseconds'),
                             lastModEndDate=stop.isoformat(timespec='milliseconds'))
        start = stop


def kev_catalog(http):
    entries = http.get(KEV)['vulnerabilities']
    if not isinstance(entries, list) or not all(isinstance(x, dict) and x.get('cveID') for x in entries):
        raise ValueError('Malformed KEV catalog')
    return {x['cveID']: x for x in entries}


def hacker_news(http, start, end, keywords):
    # Small windows avoid silently losing results to Algolia's pagination cap.
    seen = set()
    while start < end:
        stop = min(end, start + timedelta(hours=6))
        for word in keywords:
            page = 0
            while True:
                data = http.get(HN, params={'query': word, 'tags': 'story', 'page': page, 'hitsPerPage': 100,
                                           'numericFilters': f'created_at_i>={int(start.timestamp())},created_at_i<{int(stop.timestamp())}'})
                hits, pages = data['hits'], data['nbPages']
                if data.get('nbHits', 0) > 1000 or data.get('exhaustiveNbHits') is False:
                    raise ValueError('HN search window exceeds result limit; cursor retained')
                if not isinstance(hits, list) or type(pages) is not int:
                    raise ValueError('Malformed HN page')
                for hit in hits:
                    identity = hit.get('url') or f"https://news.ycombinator.com/item?id={hit['objectID']}"
                    if identity not in seen:
                        seen.add(identity)
                        yield {'id': identity, 'title': hit['title'], 'published': hit['created_at'],
                               'url': identity, 'discussion': f"https://news.ycombinator.com/item?id={hit['objectID']}"}
                page += 1
                if page >= pages:
                    break
                if not hits:
                    raise ValueError('Incomplete HN pagination')
        start = stop


def criteria(cve):
    def walk(node):
        yield from node.get('cpeMatch', [])
        for child in node.get('nodes', []) + node.get('children', []):
            yield from walk(child)
    for config in cve.get('configurations', []):
        yield from walk(config)


def normalize(cve, kev):
    score = severity = None
    for key in ('cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'):
        metrics = cve.get('metrics', {}).get(key, [])
        if metrics:
            metric = next((m for m in metrics if m.get('type') == 'Primary'), metrics[0])
            score = metric['cvssData'].get('baseScore')
            severity = metric['cvssData'].get('baseSeverity', metric.get('baseSeverity'))
            if score is not None:
                break
    products = sorted({m['criteria'] for m in criteria(cve) if m.get('vulnerable')})
    entry = kev.get(cve['id'])
    return {'cve_id': cve['id'], 'cvss': score, 'cvss_severity': severity,
            'description': next((d['value'] for d in cve.get('descriptions', []) if d.get('lang') == 'en'), 'Description unavailable'),
            'published': cve.get('published'), 'updated': cve.get('lastModified'),
            'affected_products': sorted({':'.join(p.split(':')[3:5]) for p in products}),
            'affected_cpes': products, 'affected_criteria': [m for m in criteria(cve) if m.get('vulnerable')],
            'kev': bool(entry), 'exploitation': 'Confirmed exploited (CISA KEV)' if entry else 'Unknown; not listed in KEV does not imply safe',
            'kev_details': entry,
            'remediation': entry.get('requiredAction') if entry else 'Review vendor advisory and apply the supported fixed release or mitigation; no fixed version inferred.',
            'references': sorted({r['url'] for r in cve.get('references', []) if r.get('url')} |
                                 {f"https://nvd.nist.gov/vuln/detail/{cve['id']}"})}
