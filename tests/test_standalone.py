import copy
import json
import ssl
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock, patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa

from jyoticve import bots, certificates, matching, sources
from jyoticve.core import State, deliver, fingerprint, HTTP
from jyoticve.cli import run


def cve(version='1.0'):
    return {'id': 'CVE-2026-12345', 'descriptions': [{'lang': 'en', 'value': 'A test vulnerability.'}],
            'published': '2026-09-20T00:00:00Z', 'lastModified': '2026-09-21T00:00:00Z',
            'metrics': {'cvssMetricV31': [{'cvssData': {'baseScore': 9.8, 'baseSeverity': 'CRITICAL'}}]},
            'configurations': [{'nodes': [{'operator': 'OR', 'cpeMatch': [
                {'criteria': f'cpe:2.3:a:acme:server:{version}:*:*:*:*:*:*:*', 'vulnerable': True}]}]}]}


TECH = {'id': 'server', 'name': 'Server', 'vendor': 'acme', 'product': 'server', 'version': '1.0'}


class MatchingTests(unittest.TestCase):
    def test_exact_version_and_product(self):
        self.assertEqual(matching.match_cve(cve(), [TECH])[0]['confidence'], 'confirmed')
        self.assertEqual(matching.match_cve(cve('1.1'), [TECH]), [])
        self.assertEqual(matching.match_cve(cve(), [TECH | {'vendor': 'other'}]), [])

    def test_ranges_and_unknown_version_ordering(self):
        item = cve('*')
        criteria = item['configurations'][0]['nodes'][0]['cpeMatch'][0]
        criteria.update(versionStartIncluding='1.0', versionEndExcluding='2.0')
        self.assertEqual(matching.match_cve(item, [TECH])[0]['confidence'], 'confirmed')
        self.assertEqual(matching.match_cve(item, [TECH | {'version': '2.0'}]), [])
        self.assertEqual(matching.match_cve(item, [TECH | {'version': '1.0-vendor3'}])[0]['confidence'], 'review required')

    def test_unknown_platform_in_and_needs_review(self):
        item = cve()
        config = item['configurations'][0]
        config['operator'] = 'AND'
        config['nodes'].append({'cpeMatch': [{'criteria': 'cpe:2.3:o:acme:os:5:*:*:*:*:*:*:*', 'vulnerable': False}]})
        self.assertEqual(matching.match_cve(item, [TECH])[0]['confidence'], 'review required')
        os_tech = TECH | {'id': 'os', 'part': 'o', 'product': 'os', 'version': '5'}
        self.assertEqual(matching.match_cve(item, [TECH, os_tech])[0]['confidence'], 'confirmed')
        self.assertEqual(matching.match_cve(item, [TECH, os_tech | {'version': '6'}]), [])

    def test_unrelated_or_branch_cannot_confirm_impact(self):
        item = cve()
        target = item['configurations'][0]['nodes'][0]
        constrained = {'operator': 'AND', 'nodes': [target, {'cpeMatch': [
            {'criteria': 'cpe:2.3:o:acme:os:5:*:*:*:*:*:*:*', 'vulnerable': False}]}]}
        item['configurations'] = [{'operator': 'OR', 'nodes': [constrained, {'cpeMatch': [
            {'criteria': 'cpe:2.3:a:acme:other:1.0:*:*:*:*:*:*:*', 'vulnerable': True}]}]}]
        other = TECH | {'id': 'other', 'product': 'other'}
        self.assertEqual(matching.match_cve(item, [TECH, other])[0]['confidence'], 'review required')

    def test_review_findings_are_not_confirmed_security_alerts(self):
        result = bots.cve_alert('stack', cve('*'), {}, [TECH | {'version': 'unknown'}])
        self.assertEqual(result['kind'], 'review')
        self.assertEqual(result['severity'], 'informational')


class StateTests(unittest.TestCase):
    def setUp(self):
        self.state = State(':memory:')
        self.addCleanup(self.state.close)
        self.channels = [{'id': 'security', 'type': 'webhook', 'url_env': 'TEST_WEBHOOK'}]

    def test_event_dedup_change_and_recurrence(self):
        for payload, expected in [({'status': 'bad'}, True), ({'status': 'bad'}, False),
                                  ({'status': 'good'}, True), ({'status': 'bad'}, True)]:
            self.assertEqual(self.state.event('certificates', 'host', payload, self.channels), expected)

    @patch.dict('os.environ', {'TEST_WEBHOOK': 'https://example.org/hook'})
    def test_failed_delivery_is_durable_and_successful_channels_not_resent(self):
        channels = self.channels + [{'id': 'console', 'type': 'console'}]
        self.state.event('news', 'one', {'title': 'test'}, channels)
        http = Mock()
        http.request.side_effect = RuntimeError('failed')
        with patch('builtins.print') as out:
            self.assertEqual(deliver(self.state, {'notifications': channels}, http), 1)
            http.request.side_effect = None
            self.assertEqual(deliver(self.state, {'notifications': channels}, http), 0)
            self.assertEqual(out.call_count, 1)
        self.assertEqual(http.request.call_count, 2)
        self.assertEqual(self.state.db.execute('SELECT count(*) FROM deliveries WHERE delivered IS NULL').fetchone()[0], 0)

    def test_persistence(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'state.db'
            state = State(path)
            state.event('news', 'one', {'title': 'test'}, self.channels)
            state.close()
            state = State(path)
            self.assertFalse(state.event('news', 'one', {'title': 'test'}, self.channels))
            self.assertEqual(state.db.execute('SELECT count(*) FROM deliveries WHERE delivered IS NULL').fetchone()[0], 1)
            state.close()


class CertificateTests(unittest.TestCase):
    current = datetime(2026, 9, 21, tzinfo=timezone.utc)

    def cert(self, days):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, 'example.org')])
        return (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                .serial_number(1).not_valid_before(self.current - timedelta(days=100))
                .not_valid_after(self.current + timedelta(days=days))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName('example.org')]), critical=False)
                .sign(key, hashes.SHA256()))

    def test_thresholds_and_stable_identity(self):
        cert = self.cert(15)
        with patch.object(certificates, 'read', return_value=cert):
            first = certificates.check('example.org', 443, [30, 14, 7, 3], current=self.current)
            same = certificates.check('example.org', 443, [30, 14, 7, 3], current=self.current + timedelta(hours=5))
            crossed = certificates.check('example.org', 443, [30, 14, 7, 3], current=self.current + timedelta(days=1))
        self.assertEqual(first['sans'], ['example.org'])
        self.assertEqual(certificates.issue_key(first), certificates.issue_key(same))
        self.assertNotEqual(certificates.issue_key(first), certificates.issue_key(crossed))
        self.assertEqual(crossed['threshold'], 14)

    def test_expired_untrusted_and_connection_failure(self):
        error = ssl.SSLCertVerificationError('untrusted')
        error.verify_message = 'untrusted'
        error.verify_code = 18
        with patch.object(certificates, 'read', side_effect=[error, self.cert(100)]):
            result = certificates.check('example.org', 443, [30], current=self.current)
            self.assertEqual(result['status'], 'invalid')
            self.assertEqual(result['severity'], 'critical')
        with patch.object(certificates, 'read', return_value=self.cert(-1)):
            self.assertEqual(certificates.check('example.org', 443, [30], current=self.current)['status'], 'expired')
        with patch.object(certificates, 'read', side_effect=TimeoutError('timeout')):
            self.assertEqual(certificates.check('example.org', 443, [30])['status'], 'connection failure')


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.state = State(':memory:')
        self.addCleanup(self.state.close)
        self.config = {'notifications': [{'id': 'local', 'type': 'console'}], 'initial_lookback_hours': 24}

    @patch('jyoticve.sources.hacker_news', return_value=[])
    @patch('jyoticve.sources.kev_catalog', return_value={})
    def test_failure_preserves_cursor_and_partial_events(self, *_):
        cursor = '2026-09-01T00:00:00+00:00'
        self.state.put('news:nvd_cursor', cursor)
        def partial(*args):
            yield cve()
            raise RuntimeError('outage')
        with patch('jyoticve.sources.nvd_updates', side_effect=partial):
            self.assertTrue(bots.intel('news', self.state, self.config, Mock()))
        self.assertEqual(self.state.get('news:nvd_cursor'), cursor)
        self.assertEqual(self.state.db.execute('SELECT count(*) FROM events').fetchone()[0], 1)

    @patch('jyoticve.sources.hacker_news', return_value=[])
    @patch('jyoticve.sources.kev_catalog', return_value={})
    def test_timestamp_only_update_does_not_repeat(self, *_):
        for timestamp in ['2026-09-21T00:00:00Z', '2026-09-21T01:00:00Z']:
            item = cve()
            item['lastModified'] = timestamp
            with patch('jyoticve.sources.nvd_updates', return_value=[item]):
                bots.intel('news', self.state, self.config, Mock())
        self.assertEqual(self.state.db.execute('SELECT count(*) FROM events').fetchone()[0], 1)

    @patch('jyoticve.sources.hacker_news', return_value=[])
    @patch('jyoticve.sources.nvd_updates', return_value=[])
    def test_old_cve_new_kev_entry_alerts(self, *_):
        self.state.put('news:kev_processed', {'CVE-older': 'old'})
        entry = {'cveID': cve()['id'], 'dateAdded': '2026-09-21', 'requiredAction': 'Apply update'}
        with patch('jyoticve.sources.kev_catalog', return_value={cve()['id']: entry}), \
             patch('jyoticve.sources.nvd_pages', return_value=[cve()]):
            bots.intel('news', self.state, self.config, Mock())
        payload = json.loads(self.state.db.execute('SELECT payload FROM events').fetchone()[0])
        self.assertTrue(payload['details']['kev'])
        self.assertEqual(payload['severity'], 'critical')

    def test_daily_summary_and_issue_dedup(self):
        result = {'domain': 'example.org:443', 'status': 'expiring', 'severity': 'medium', 'threshold': 30}
        with patch.object(certificates, 'domains', return_value=[('example.org', 443)]), \
             patch.object(certificates, 'check', return_value=result):
            config = self.config | {'domains_file': 'unused', 'certificate_thresholds': [30]}
            bots.tls(self.state, config, Mock())
            bots.tls(self.state, config, Mock())
        self.assertEqual(self.state.db.execute('SELECT count(*) FROM events').fetchone()[0], 2)

    def test_dry_run_does_not_write_database_or_send(self):
        with tempfile.TemporaryDirectory() as folder:
            config = self.config | {'state_file': str(Path(folder) / 'state.db')}
            def fake(state, config, http):
                state.event('news', 'test', {'title': 'preview'}, config['notifications'])
                return []
            with patch.dict('jyoticve.cli.BOTS', {'news': fake}), patch.object(HTTP, 'request') as request, patch('builtins.print'):
                self.assertTrue(run('news', config, dry_run=True))
                request.assert_not_called()
            self.assertFalse(Path(config['state_file']).exists())


class SourceTests(unittest.TestCase):
    def test_nvd_pagination_failure(self):
        http = Mock()
        http.get.side_effect = [{'vulnerabilities': [{'cve': cve()}], 'totalResults': 2},
                                {'vulnerabilities': [], 'totalResults': 2}]
        with self.assertRaises(ValueError):
            list(sources.nvd_pages(http))

    def test_nvd_long_outage_is_split_into_legal_windows(self):
        start = datetime(2025, 1, 1, tzinfo=timezone.utc)
        with patch.object(sources, 'nvd_pages', return_value=[]) as pages:
            list(sources.nvd_updates(Mock(), start, start + timedelta(days=250)))
        self.assertEqual(pages.call_count, 3)
        for call in pages.call_args_list:
            self.assertLessEqual(datetime.fromisoformat(call.kwargs['lastModEndDate']) -
                                 datetime.fromisoformat(call.kwargs['lastModStartDate']), timedelta(days=120))

    @patch('jyoticve.core.time.sleep')
    def test_retry_after_rate_limit(self, sleep):
        http = HTTP()
        response = Mock(status_code=429, headers={'Retry-After': '3'})
        success = Mock(status_code=200, json=lambda: {'ok': True})
        http.session.request = Mock(side_effect=[response, success])
        self.assertEqual(http.get('https://example.org'), {'ok': True})
        sleep.assert_called_once_with(3.0)


class UpdateAndDeliveryTests(unittest.TestCase):
    def test_cve_changes_and_rejection_are_reported_once(self):
        state = State(':memory:')
        self.addCleanup(state.close)
        config = {'notifications': [{'id': 'local', 'type': 'console'}]}
        original = cve()
        changed = copy.deepcopy(original)
        changed['metrics']['cvssMetricV31'][0]['cvssData']['baseScore'] = 7.5
        rejected = changed | {'vulnStatus': 'Rejected'}
        with patch.object(sources, 'kev_catalog', return_value={}), patch.object(sources, 'hacker_news', return_value=[]):
            for item in (original, changed, changed, rejected, rejected):
                with patch.object(sources, 'nvd_updates', return_value=[item]):
                    bots.intel('news', state, config, Mock())
        payloads = [json.loads(row[0]) for row in state.db.execute('SELECT payload FROM events ORDER BY id')]
        self.assertEqual(len(payloads), 3)
        self.assertEqual(payloads[-1]['kind'], 'resolution')

    @patch.dict('os.environ', {'TEST_SLACK': 'https://example.org/hook'})
    def test_multipart_delivery_resumes_at_failed_chunk(self):
        state = State(':memory:')
        self.addCleanup(state.close)
        channels = [{'id': 'slack', 'type': 'slack', 'url_env': 'TEST_SLACK'}]
        state.event('news', 'long', {'title': 'long', 'summary': 'x' * 7000}, channels)
        http = Mock()
        http.request.side_effect = [Mock(), RuntimeError('outage')]
        self.assertEqual(deliver(state, {'notifications': channels}, http), 1)
        self.assertEqual(state.db.execute('SELECT parts_sent FROM deliveries').fetchone()[0], 1)
        http.request.reset_mock()
        http.request.side_effect = None
        self.assertEqual(deliver(state, {'notifications': channels}, http), 0)
        self.assertEqual(http.request.call_count, 1)
        self.assertTrue(http.request.call_args.kwargs['headers']['Idempotency-Key'].endswith('-1'))
