import io
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

from jyoticve.web import Dashboard, Handler


class DashboardTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name)
        self.path = self.root / 'config.json'
        config = json.loads(Path('config.example.json').read_text())
        self.path.write_text(json.dumps(config))
        (self.root / 'domains.txt').write_text('')
        (self.root / 'inventory.json').write_text('[]')
        self.dashboard = Dashboard(self.path)
        self.addCleanup(self.dashboard.close)

    def test_empty_workspace_snapshot(self):
        result = self.dashboard.snapshot()
        self.assertEqual(result['events'], [])
        self.assertEqual(result['scheduler'], 'stopped')
        self.assertNotIn('token', result)
        self.assertEqual(result['pending'], 0)

    def test_domains_validation_and_atomic_save(self):
        self.dashboard.save('domains', {'domains': 'example.com\n'})
        with self.assertRaises(ValueError):
            self.dashboard.save('domains', {'domains': 'https://example.com/path'})
        self.assertEqual((self.root / 'domains.txt').read_text(), 'example.com\n')

    def test_inventory_validation_preserves_existing_data(self):
        tech = {'id': 'web', 'name': 'Web', 'version': '1.0', 'vendor': 'acme', 'product': 'web'}
        self.dashboard.save('inventory', {'inventory': [tech]})
        with self.assertRaises(ValueError):
            self.dashboard.save('inventory', {'inventory': [{'name': 'bad'}]})
        self.assertEqual(self.dashboard.snapshot()['inventory'][0]['id'], 'web')

    def test_settings_and_no_file_path_mutation(self):
        with self.assertRaises(ValueError):
            self.dashboard.save('settings', {'state_file': '/tmp/other.db'})
        self.dashboard.save('settings', {'certificate_thresholds': [20, 5]})
        self.assertEqual(self.dashboard.config()['certificate_thresholds'], [20, 5])
        before = self.path.read_text()
        with self.assertRaises(ValueError):
            self.dashboard.save('settings', {'certificate_thresholds': [-1]})
        self.assertEqual(self.path.read_text(), before)

    def test_schedule_changes_are_due_and_saved(self):
        schedules = {bot: {'enabled': True, 'interval_seconds': 120} for bot in ('news', 'certificates', 'stack')}
        self.dashboard.save('settings', {'schedules': schedules})
        self.assertEqual(self.dashboard.snapshot()['next_due']['news'], 0)

    def test_real_empty_certificate_preview_and_output(self):
        result = self.dashboard.scan({'bot': 'certificates', 'preview': True})
        deadline = time.monotonic() + 10
        while self.dashboard.jobs[result['job_id']]['status'] == 'running' and time.monotonic() < deadline:
            time.sleep(.05)
        job = self.dashboard.snapshot()['jobs'][0]
        self.assertEqual(job['status'], 'success', job['output'])
        self.assertIn('TLS daily summary', job['output'])
        self.assertEqual(self.dashboard.snapshot()['runs'], [])
        self.assertEqual(self.dashboard.snapshot()['events'], [])

    def handler(self, path, body, token=True, origin=None, host=None):
        handler = Handler.__new__(Handler)
        handler.server = Mock(dashboard=self.dashboard, server_port=8080)
        handler.path = path
        raw = json.dumps(body).encode()
        handler.headers = {'Host': host or '127.0.0.1:8080', 'Content-Type': 'application/json', 'Content-Length': str(len(raw))}
        if token:
            handler.headers['X-Dashboard-Token'] = self.dashboard.token
        if origin:
            handler.headers['Origin'] = origin
        handler.rfile = io.BytesIO(raw)
        handler.reply = Mock()
        return handler

    def test_csrf_and_dns_rebinding_rejected(self):
        for kwargs in ({'token': False}, {'origin': 'https://evil.example'}, {'host': 'evil.example:8080'}):
            handler = self.handler('/api/domains', {'domains': 'example.com'}, **kwargs)
            handler.do_POST()
            self.assertEqual(handler.reply.call_args.args[0], 403)
        self.assertEqual((self.root / 'domains.txt').read_text(), '')

    def test_valid_api_write_and_invalid_payload(self):
        handler = self.handler('/api/domains', {'domains': 'example.com'}, origin='http://127.0.0.1:8080')
        handler.do_POST()
        self.assertEqual(handler.reply.call_args.args[0], 200)
        handler = self.handler('/api/scan', {'bot': 'unknown'})
        handler.do_POST()
        self.assertEqual(handler.reply.call_args.args[0], 400)

    def test_static_routes_and_no_path_traversal(self):
        for path, status in (('/', 200), ('/app.js', 200), ('/style.css', 200), ('/../../config.json', 404)):
            handler = self.handler(path, {})
            handler.do_GET()
            self.assertEqual(handler.reply.call_args.args[0], status)

    @patch('jyoticve.web.subprocess.Popen')
    def test_scheduler_control(self, popen):
        process = popen.return_value
        process.poll.return_value = None
        self.dashboard.scheduling(True)
        self.dashboard.scheduling(True)
        popen.assert_called_once()
        self.dashboard.scheduling(False)
        process.terminate.assert_called_once()
        self.assertEqual(self.dashboard.snapshot()['scheduler'], 'stopping')
        process.poll.return_value = 0
        self.assertEqual(self.dashboard.snapshot()['scheduler'], 'stopped')

    def test_external_scheduler_is_detected_and_not_duplicated(self):
        from jyoticve.cli import lock
        with lock(self.dashboard.config()['state_file'] + '.scheduler.lock'):
            self.assertEqual(self.dashboard.snapshot()['scheduler'], 'external')
            with self.assertRaises(ValueError):
                self.dashboard.scheduling(True)
        self.assertEqual(self.dashboard.snapshot()['scheduler'], 'stopped')

    def test_event_details_are_loaded_separately(self):
        state = self.dashboard.state()
        state.event('news', 'sample', {'title': 'Sample', 'details': {'description': 'Full description'}}, [])
        state.close()
        listing = self.dashboard.snapshot()['events'][0]
        self.assertNotIn('details', listing['payload'])
        self.assertEqual(self.dashboard.event(listing['id'])['payload']['details']['description'], 'Full description')
        self.assertIsNone(self.dashboard.event(999))
