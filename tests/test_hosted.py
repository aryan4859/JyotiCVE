import base64
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from jyoticve.hosted import bootstrap, create_app, ManagedDashboard, settings_from_environment


class HostedTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name)
        self.env = {'JYOTICVE_ADMIN_USER': 'admin', 'JYOTICVE_ADMIN_PASSWORD': 'a-long-test-password-only-for-tests',
                    'JYOTICVE_DATA_DIR': str(self.root), 'RENDER_EXTERNAL_URL': 'https://monitor.onrender.com'}
        self.app = create_app(self.env, start_monitor=False)
        self.addCleanup(self.app.dashboard.close)
        self.client = self.app.test_client()
        self.auth = 'Basic ' + base64.b64encode(b'admin:a-long-test-password-only-for-tests').decode()
        self.headers = {'Authorization': self.auth}
        self.origin = self.env['RENDER_EXTERNAL_URL']

    def get(self, path, **kwargs):
        return self.client.get(path, base_url=self.origin, **kwargs)

    def post(self, path, body, **kwargs):
        headers = self.headers | {'Origin': self.origin, 'X-Dashboard-Token': self.app.dashboard.token}
        headers.update(kwargs)
        return self.client.post(path, json=body, base_url=self.origin, headers=headers)

    def test_no_anonymous_dashboard_or_api_access(self):
        for path in ('/', '/app.js', '/api/session', '/api/state', '/api/events/1'):
            response = self.get(path)
            self.assertEqual(response.status_code, 401, path)
            self.assertIn('Basic realm=', response.headers['WWW-Authenticate'])
        wrong = self.get('/api/state', headers={'Authorization': 'Basic Zm9vOmJhcg=='})
        self.assertEqual(wrong.status_code, 401)

    def test_health_check_is_public_and_minimal(self):
        response = self.client.get('/healthz', base_url='http://internal-healthcheck')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json, {'status': 'ok'})
        self.app.dashboard.close()
        self.assertEqual(self.get('/healthz').status_code, 503)

    def test_authenticated_state_assets_and_security_headers(self):
        for path in ('/', '/app.js', '/style.css', '/api/state', '/api/session'):
            response = self.get(path, headers=self.headers)
            self.assertEqual(response.status_code, 200, path)
            self.assertEqual(response.headers['Cache-Control'], 'no-store')
            self.assertEqual(response.headers['X-Frame-Options'], 'DENY')
            response.close()
        self.assertNotIn(self.env['JYOTICVE_ADMIN_PASSWORD'], self.get('/api/state', headers=self.headers).text)

    def test_host_and_origin_and_token_are_enforced(self):
        response = self.client.get('/api/state', base_url='https://attacker.example', headers=self.headers)
        self.assertEqual(response.status_code, 403)
        for overrides in ({'Origin': 'https://attacker.example'}, {'Origin': ''}, {'X-Dashboard-Token': ''}):
            self.assertEqual(self.post('/api/domains', {'domains': 'example.com'}, **overrides).status_code, 403)
        self.assertEqual(self.post('/api/domains', {'domains': 'example.com\n'}).status_code, 200)
        self.assertEqual((self.root / 'domains.txt').read_text(), 'example.com\n')

    def test_configuration_survives_redeploy(self):
        self.post('/api/domains', {'domains': 'my-domain.example\n'})
        self.post('/api/settings', {'certificate_thresholds': [21, 7]})
        state = self.app.dashboard.state()
        state.put('news:nvd_cursor', '2026-09-21T00:00:00+00:00')
        state.close()
        self.app.dashboard.close()
        recreated = create_app(self.env, start_monitor=False)
        self.addCleanup(recreated.dashboard.close)
        self.assertEqual(recreated.dashboard.snapshot()['domains'], 'my-domain.example\n')
        self.assertEqual(recreated.dashboard.config()['certificate_thresholds'], [21, 7])
        state = recreated.dashboard.state()
        self.assertEqual(state.get('news:nvd_cursor'), '2026-09-21T00:00:00+00:00')
        state.close()

    def test_pausing_survives_redeploy(self):
        self.assertEqual(self.post('/api/scheduler', {'enabled': False}).status_code, 200)
        self.app.dashboard.close()
        recreated = create_app(self.env, start_monitor=False)
        self.addCleanup(recreated.dashboard.close)
        with patch('jyoticve.web.subprocess.Popen') as popen:
            recreated.dashboard.supervisor_tick()
            popen.assert_not_called()
        self.assertFalse(recreated.dashboard.scheduler_wanted)

    @patch('jyoticve.web.subprocess.Popen')
    def test_scheduler_autostart_restart_and_single_instance(self, popen):
        first, second = Mock(), Mock()
        first.poll.return_value = None
        second.poll.return_value = None
        popen.side_effect = [first, second]
        dashboard = self.app.dashboard
        dashboard.supervisor_tick()
        dashboard.supervisor_tick()
        self.assertEqual(popen.call_count, 1)
        first.poll.return_value = 1
        dashboard.supervisor_tick()
        self.assertEqual(popen.call_count, 2)
        self.assertIs(dashboard.scheduler, second)
        with self.assertRaises(RuntimeError):
            ManagedDashboard(dashboard.path, start_monitor=False)
        dashboard.close()
        second.terminate.assert_called_once()

    def test_storage_cannot_escape_persistent_directory(self):
        self.app.dashboard.close()
        config_path = self.root / 'config.json'
        config = json.loads(config_path.read_text())
        config['state_file'] = '../outside.db'
        config_path.write_text(json.dumps(config))
        with self.assertRaises(ValueError):
            bootstrap(self.root)

    def test_invalid_input_and_unknown_routes(self):
        self.assertEqual(self.post('/api/scheduler', {'enabled': 'yes'}).status_code, 400)
        self.assertEqual(self.post('/api/settings', {'certificate_thresholds': [-1]}).status_code, 400)
        self.assertEqual(self.post('/api/domains', []).status_code, 400)
        self.assertEqual(self.post('/api/unknown', {}).status_code, 404)
        self.assertEqual(self.get('/config.json', headers=self.headers).status_code, 404)
        self.assertEqual(self.get('/api/events/999', headers=self.headers).status_code, 404)
        response = self.client.post('/api/domains', data='x' * 262145, base_url=self.origin,
                                    headers=self.headers | {'Origin': self.origin, 'X-Dashboard-Token': self.app.dashboard.token,
                                                            'Content-Type': 'application/json'})
        self.assertEqual(response.status_code, 413)

    def test_missing_secrets_and_non_https_origins_fail_startup(self):
        for overrides in ({'JYOTICVE_ADMIN_PASSWORD': ''}, {'JYOTICVE_DATA_DIR': 'relative'},
                          {'RENDER_EXTERNAL_URL': 'http://monitor.example'}, {'RENDER_EXTERNAL_URL': 'https://x.example/path'}):
            with self.assertRaises(ValueError):
                settings_from_environment(self.env | overrides)

    def test_packaged_defaults_match_example(self):
        self.assertEqual(json.loads(Path('jyoticve/default-config.json').read_text()),
                         json.loads(Path('config.example.json').read_text()))
