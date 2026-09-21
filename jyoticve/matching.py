"""Conservative CPE and version matching; never infer impact from description substrings."""
import json
import re
from pathlib import Path

from packaging.version import InvalidVersion, Version


def cpe_parts(value):
    parts = re.split(r'(?<!\\):', value)
    if len(parts) != 13 or parts[:2] != ['cpe', '2.3']:
        raise ValueError('Expected a complete CPE 2.3 formatted string')
    return parts


def inventory(path):
    entries = json.loads(Path(path).read_text())
    if not isinstance(entries, list):
        raise ValueError('Inventory must be an array')
    ids = set()
    for entry in entries:
        if not all(isinstance(entry.get(k), str) and entry[k].strip() for k in ('id', 'name', 'version')):
            raise ValueError('Each inventory entry needs id, name and exact version strings')
        if entry['id'] in ids:
            raise ValueError('Inventory IDs must be unique')
        ids.add(entry['id'])
        if entry.get('cpe'):
            parts = cpe_parts(entry['cpe'])
            entry.setdefault('part', parts[2])
            entry.setdefault('vendor', parts[3])
            entry.setdefault('product', parts[4])
            if parts[5] not in ('*', entry['version']):
                raise ValueError('Inventory CPE version conflicts with deployed version')
        if not all(isinstance(entry.get(k), str) and entry[k] not in ('', '*', '-') for k in ('vendor', 'product')):
            raise ValueError('Map every technology/package to exact NVD vendor/product or CPE identifiers')
        aliases = entry.get('aliases', [])
        if not isinstance(aliases, list) or not all(isinstance(a, list) and len(a) == 2 and
                all(isinstance(v, str) and v not in ('', '*', '-') for v in a) for a in aliases):
            raise ValueError('aliases must be arrays of exact vendor/product pairs')
        if entry.get('part', 'a') not in ('a', 'o', 'h'):
            raise ValueError('CPE part must be a (application), o (OS), or h (hardware)')
    return entries


def product_matches(parts, tech):
    identities = [(tech['vendor'], tech['product'])] + [tuple(a) for a in tech.get('aliases', [])]
    return parts[2] == tech.get('part', 'a') and any(
        (parts[3].lower(), parts[4].lower()) == (v.lower(), p.lower()) for v, p in identities)


def version_matches(match, tech):
    """True/False/None: None means vendor-specific ordering or constraints need review."""
    parts = cpe_parts(match['criteria'])
    deployed = tech['version']
    if deployed in ('*', '-', 'unknown'):
        return None
    exact = parts[5]
    if exact not in ('*', '-'):
        if '*' in exact or '?' in exact or '\\' in exact:
            return None
        if exact.lower() != deployed.lower():
            return False
    elif exact == '-':
        return None
    bounds = [('versionStartIncluding', lambda a, b: a >= b),
              ('versionStartExcluding', lambda a, b: a > b),
              ('versionEndIncluding', lambda a, b: a <= b),
              ('versionEndExcluding', lambda a, b: a < b)]
    # Numeric release ordering is portable. Other schemes require explicit opt-in.
    for key, operation in bounds:
        if key in match:
            if tech.get('version_scheme', 'numeric') == 'numeric' and not all(
                    re.fullmatch(r'\d+(?:\.\d+)*', v) for v in (deployed, match[key])):
                return None
            if tech.get('version_scheme', 'numeric') not in ('numeric', 'pep440'):
                return None
            try:
                if not operation(Version(deployed), Version(match[key])):
                    return False
            except InvalidVersion:
                return None
    # OS, edition, architecture, language, and update constraints cannot be ignored.
    known = cpe_parts(tech['cpe']) if tech.get('cpe') else None
    for i in range(6, 13):
        if parts[i] != '*':
            if known is None or known[i] == '*':
                return None
            if known[i].lower() != parts[i].lower():
                return False
    return True


def combine(values, operator):
    if not values:
        return None
    if operator == 'AND':
        return False if False in values else (None if None in values else True)
    return True if True in values else (None if None in values else False)


def match_cve(cve, technologies):
    findings = []
    for tech in technologies:
        def evaluate(node):
            branches = []
            for item in node.get('cpeMatch', []):
                parts = cpe_parts(item['criteria'])
                candidates = [t for t in technologies if product_matches(parts, t)]
                truth = combine([version_matches(item, t) for t in candidates], 'OR')
                target = False
                evidence = []
                if item.get('vulnerable') and product_matches(parts, tech):
                    target = version_matches(item, tech)
                    if target is not False:
                        evidence = [item]
                branches.append((truth, target, evidence))
            branches.extend(evaluate(child) for child in node.get('nodes', []) + node.get('children', []))
            operator = node.get('operator', 'OR')
            truth = combine([b[0] for b in branches], operator)
            target = combine([b[1] for b in branches], 'OR') if branches else False
            if operator == 'AND':
                target = combine([truth, target], 'AND')
            evidence = [e for b in branches if b[1] is not False for e in b[2]]
            if node.get('negate'):
                truth = None if truth is None else not truth
                target = None if evidence else False
            return truth, target, evidence

        results = [evaluate(config) for config in cve.get('configurations', [])]
        relevant = [r for r in results if r[1] is not False and r[2]]
        if relevant:
            confirmed = combine([r[1] for r in relevant], 'OR') is True
            findings.append({'technology': tech['name'], 'inventory_id': tech['id'],
                             'category': tech.get('category', 'other'), 'package': tech.get('package'),
                             'deployed_version': tech['version'], 'affected_versions': [e for r in relevant for e in r[2]],
                             'confidence': 'confirmed' if confirmed else 'review required',
                             'scope': 'CPE/version applicability; verify deployment prerequisites in the vendor advisory'})
    return findings
