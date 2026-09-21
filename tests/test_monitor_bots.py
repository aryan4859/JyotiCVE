import json
import ssl
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock, patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / '.github/scripts'))
import cert_expiry_bot as cert
import tech_stack_cve_bot as tech


class CertificateTests(unittest.TestCase):
    now = datetime(2026, 9, 21, tzinfo=timezone.utc)

    def certificate(self, days, starts=-10):
        return Mock(not_valid_after_utc=self.now + timedelta(days=days),
                    not_valid_before_utc=self.now + timedelta(days=starts))

    def test_expiry_boundaries(self):
        for days, expected in [(-1, 'EXPIRED'), (0, 'EXPIRED'), (30, 'EXPIRING SOON'), (31, 'VALID')]:
            with self.subTest(days=days), patch.object(cert, 'read_certificate', return_value=self.certificate(days)):
                self.assertEqual(cert.check_certificate('example.org', now=self.now)['Status'], expected)

    def test_invalid_certificate_dates_still_available(self):
        error = ssl.SSLCertVerificationError('expired')
        error.verify_message = 'certificate has expired'
        with patch.object(cert, 'read_certificate', side_effect=[error, self.certificate(-1)]) as read:
            result = cert.check_certificate('example.org', now=self.now)
        self.assertEqual(result['Status'], 'EXPIRED')
        self.assertEqual(result['TLS validation'], 'certificate has expired')
        context = read.call_args.args[2]
        self.assertEqual(context.verify_mode, ssl.CERT_NONE)
        self.assertFalse(context.check_hostname)

    def test_untrusted_certificate_never_reported_valid(self):
        error = ssl.SSLCertVerificationError('hostname mismatch')
        error.verify_message = 'hostname mismatch'
        with patch.object(cert, 'read_certificate', side_effect=[error, self.certificate(60)]):
            result = cert.check_certificate('example.org', now=self.now)
        self.assertEqual(result['Status'], 'INVALID TLS CERTIFICATE')

    def test_future_and_unreachable(self):
        with patch.object(cert, 'read_certificate', return_value=self.certificate(60, 2)):
            self.assertEqual(cert.check_certificate('example.org', now=self.now)['Status'], 'NOT YET VALID')
        with patch.object(cert, 'read_certificate', side_effect=TimeoutError('timed out')):
            self.assertEqual(cert.check_certificate('example.org')['Status'], 'CHECK FAILED')

    def test_parse_der_certificate_with_sni(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, 'example.org')])
        expiry = self.now + timedelta(days=90)
        certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                       .public_key(key.public_key()).serial_number(1)
                       .not_valid_before(self.now).not_valid_after(expiry).sign(key, hashes.SHA256()))
        context = Mock()
        tls = context.wrap_socket.return_value.__enter__ = Mock()
        tls.return_value.getpeercert.return_value = certificate.public_bytes(serialization.Encoding.DER)
        context.wrap_socket.return_value.__exit__ = Mock(return_value=False)
        from unittest.mock import MagicMock
        with patch.object(cert.socket, 'create_connection', return_value=MagicMock()):
            parsed = cert.read_certificate('example.org', 443, context, 10)
        self.assertEqual(parsed.not_valid_after_utc, expiry)
        self.assertEqual(context.wrap_socket.call_args.kwargs['server_hostname'], 'example.org')

    def test_domain_list_and_bad_url(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'domains.txt'
            path.write_text('# comment\nexample.org\nexample.org\napp.example.org:8443 # custom\n')
            self.assertEqual(cert.load_domains(path), [('example.org', 443), ('app.example.org', 8443)])
            for invalid in ('https://example.org/path', 'example.org:0', '[broken'):
                path.write_text(invalid)
                with self.assertRaises(ValueError):
                    cert.load_domains(path)

    def test_one_failed_host_does_not_skip_others(self):
        with patch.object(cert, 'check_certificate', side_effect=[{'Status': 'CHECK FAILED'}, {'Status': 'EXPIRED'}]) as check, \
             patch.object(cert.common, 'send_telegram_alert', return_value=True) as send:
            with self.assertRaises(RuntimeError):
                cert.run([('a.org', 443), ('b.org', 443)])
        self.assertEqual(check.call_count, 2)
        self.assertEqual(send.call_count, 2)


class TechStackTests(unittest.TestCase):
    package = {'name': 'django', 'ecosystem': 'PyPI', 'version': '4.2.16'}

    def test_query_payload_and_empty_page_pagination(self):
        first = Mock(status_code=200, json=lambda: {'next_page_token': 'next'})
        second = Mock(status_code=200, json=lambda: {'vulns': [{'id': 'GHSA-1'}, {'id': 'OSV-withdrawn', 'withdrawn': '2025'}]})
        payloads = []
        def post(url, json, timeout):
            payloads.append(dict(json))
            return [first, second][len(payloads) - 1]
        with patch.object(tech.common.SESSION, 'post', side_effect=post):
            results = tech.query_osv(self.package)
        self.assertEqual(results, [{'id': 'GHSA-1'}])
        self.assertEqual(payloads[0], {'package': {'name': 'django', 'ecosystem': 'PyPI'}, 'version': '4.2.16'})
        self.assertEqual(payloads[1]['page_token'], 'next')

    @patch.object(tech.time, 'sleep')
    def test_api_error_or_invalid_json_is_not_no_findings(self, sleep):
        response = Mock(status_code=400)
        response.raise_for_status.side_effect = tech.requests.HTTPError()
        with patch.object(tech.common.SESSION, 'post', return_value=response):
            with self.assertRaises(RuntimeError):
                tech.query_osv(self.package)
        response = Mock(status_code=200, json=lambda: [])
        with patch.object(tech.common.SESSION, 'post', return_value=response):
            with self.assertRaises(RuntimeError):
                tech.query_osv(self.package)

    def test_persistent_dedup_aliases_package_version_and_failures(self):
        vuln = {'id': 'GHSA-1', 'aliases': ['CVE-2026-12345']}
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'state.json'
            history = tech.FindingHistory(path)
            with patch.object(tech.common, 'send_telegram_alert', side_effect=[False, True, True]) as send:
                self.assertEqual(history.deliver(self.package, vuln, {}), -1)
                self.assertFalse(path.exists())
                self.assertEqual(history.deliver(self.package, vuln, {}), 1)
                history = tech.FindingHistory(path)
                self.assertEqual(history.deliver(self.package, {'id': 'CVE-2026-12345'}, {}), 0)
                self.assertEqual(history.deliver(dict(self.package, version='4.2.15'), vuln, {}), 1)
                self.assertEqual(send.call_count, 3)

    def test_kev_epss_and_package_specific_fixes(self):
        vuln = {'id': 'GHSA-1', 'aliases': ['CVE-2026-12345'], 'details': 'a' * 6000,
                'affected': [
                    {'package': {'name': 'django', 'ecosystem': 'PyPI'}, 'ranges': [{'type': 'ECOSYSTEM', 'events': [{'fixed': '4.2.17'}]}]},
                    {'package': {'name': 'other', 'ecosystem': 'npm'}, 'ranges': [{'events': [{'fixed': '9.9.9'}]}]}]}
        result = tech.finding_details(self.package, vuln, {'CVE-2026-12345': {'requiredAction': 'Patch'}}, {})
        self.assertIn('KNOWN EXPLOITED', result['CISA KEV'])
        self.assertIn('Not available', result['EPSS'])
        self.assertEqual(result['Fix versions listed by advisory'], '4.2.17')
        self.assertEqual(len(result['Details']), 6000)

    def test_dry_run_does_not_send_or_save(self):
        history = Mock()
        with patch.object(tech, 'query_osv', return_value=[{'id': 'OSV-1'}]), \
             patch.object(tech.common, 'send_telegram_alert') as send:
            tech.run([self.package], history, dry_run=True)
        history.deliver.assert_not_called()
        send.assert_not_called()

    def test_failed_package_does_not_hide_other_findings(self):
        history = Mock()
        history.deliver.return_value = 1
        with patch.object(tech, 'query_osv', side_effect=[RuntimeError('OSV failed'), [{'id': 'OSV-1'}]]), \
             patch.object(tech.common, 'send_telegram_alert', return_value=True):
            with self.assertRaises(RuntimeError):
                tech.run([self.package, dict(self.package, name='other')], history)
        history.deliver.assert_called_once()

    def test_stack_rejects_missing_or_numeric_versions(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'stack.json'
            for value in [{}, [{'name': 'django'}], [dict(self.package, version=4.2)]]:
                path.write_text(json.dumps(value))
                with self.assertRaises(ValueError):
                    tech.load_stack(path)
