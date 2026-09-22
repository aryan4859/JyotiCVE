"""Integration tests against a disposable PostgreSQL database, never DATABASE_URL.

Run with JYOTICVE_TEST_DATABASE_URL pointing at a local test database.
Each test uses its own schema and removes only that schema afterward.
"""
import base64
import json
import os
from pathlib import Path
import subprocess
import socket
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
import uuid

from jyoticve.cli import lock, run
from jyoticve.core import State, deliver
from jyoticve.hosted import create_app, settings_from_environment
from jyoticve.storage import connection_url


class EnvironmentTests(unittest.TestCase):
    def test_prisma_pool_url_uses_direct_endpoint(self):
        self.assertEqual(connection_url('postgres://user:secret@pooled.db.prisma.io:5432/db?sslmode=require'),
                         'postgres://user:secret@db.prisma.io:5432/db?sslmode=require')

    def test_dotenv_loads_without_overriding_environment(self):
        with tempfile.TemporaryDirectory() as folder:
            Path(folder, '.env').write_text('NVD_API_KEY=example-from-file\nJYOTICVE_ADMIN_USER=from-file\n')
            env = dict(os.environ, PYTHONPATH=str(Path.cwd()), JYOTICVE_ADMIN_USER='from-environment')
            env.pop('NVD_API_KEY', None)
            result = subprocess.run([sys.executable, '-c',
                'import jyoticve, os; print(os.environ["NVD_API_KEY"]); print(os.environ["JYOTICVE_ADMIN_USER"])'],
                cwd=folder, env=env, capture_output=True, text=True, check=True)
            self.assertEqual(result.stdout.splitlines(), ['example-from-file', 'from-environment'])

    def test_postgres_does_not_require_data_directory(self):
        env = {'DATABASE_URL': 'postgresql://user:password@localhost/test',
               'JYOTICVE_ADMIN_PASSWORD': 'test-password-at-least-24-characters',
               'RENDER_EXTERNAL_URL': 'https://monitor.example.com'}
        self.assertEqual(settings_from_environment(env)[3], 'postgres:')
        self.assertEqual(settings_from_environment(env | {'JYOTICVE_DATA_DIR': 'invalid'})[3], 'postgres:')
        with self.assertRaisesRegex(ValueError, 'PostgreSQL connection URL'):
            settings_from_environment(env | {'DATABASE_URL': 'https://provider.example.com'})


@unittest.skipUnless(os.environ.get('JYOTICVE_TEST_DATABASE_URL'), 'Set JYOTICVE_TEST_DATABASE_URL for PostgreSQL integration tests')
class PostgresTests(unittest.TestCase):
    def setUp(self):
        import psycopg
        from psycopg import sql
        url = connection_url(os.environ['JYOTICVE_TEST_DATABASE_URL'])
        self.schema = 'jyoticve_test_' + uuid.uuid4().hex
        self.admin = psycopg.connect(url, autocommit=True)
        self.admin.execute(sql.SQL('CREATE SCHEMA {}').format(sql.Identifier(self.schema)))
        self.addCleanup(self.admin.close)
        self.addCleanup(lambda: self.admin.execute(sql.SQL('DROP SCHEMA {} CASCADE').format(sql.Identifier(self.schema))))
        suffix = '&' if '?' in url else '?'
        self.env = patch.dict(os.environ, {
            'DATABASE_URL': url + suffix + 'options=-csearch_path%3D' + self.schema,
            'DATABASE_DIRECT_URL': '',
            'JYOTICVE_DATA_DIR': '', 'JYOTICVE_ADMIN_USER': 'admin',
            'JYOTICVE_ADMIN_PASSWORD': 'test-password-at-least-24-characters',
            'JYOTICVE_PUBLIC_ORIGIN': 'https://monitor.example.com',
        })
        self.env.start()
        self.addCleanup(self.env.stop)
        self.app = create_app(start_monitor=False)
        self.addCleanup(lambda: self.app.dashboard.close())

    def test_startup_api_and_persistence_without_disk(self):
        dashboard = self.app.dashboard
        self.assertEqual(str(dashboard.path), 'postgres:config')
        dashboard.save('domains', {'domains': 'example.org\n'})
        dashboard.save('inventory', {'inventory': [{'id': 'python', 'name': 'Python', 'version': '3.13.0', 'vendor': 'python', 'product': 'python'}]})
        dashboard.save('settings', {'certificate_thresholds': [14, 7]})
        state = dashboard.state()
        state.put('news:next_due', 123)
        state.event('news', 'test', {'title': 'Persisted', 'severity': 'high'}, [{'id': 'console'}])
        state.close()
        dashboard.scheduling(False)
        dashboard.close()
        self.app = create_app(start_monitor=False)
        client = self.app.test_client()
        auth = base64.b64encode(b'admin:test-password-at-least-24-characters').decode()
        response = client.get('/api/state', base_url='https://monitor.example.com', headers={'Authorization': 'Basic ' + auth})
        self.assertEqual(response.status_code, 200, response.text)
        data = response.json
        self.assertEqual(data['domains'], 'example.org\n')
        self.assertEqual(data['inventory'][0]['id'], 'python')
        self.assertEqual(data['settings']['certificate_thresholds'], [14, 7])
        self.assertEqual(data['counts'], {'high': 1})
        self.assertEqual(data['pending'], 1)
        self.assertEqual(data['next_due']['news'], 123)
        self.assertFalse(self.app.dashboard.scheduler_wanted)
        self.assertEqual(client.get('/healthz').status_code, 200)
        self.assertEqual(client.get('/api/state', base_url='https://monitor.example.com').status_code, 401)

    def test_event_transaction_deduplication_and_delivery(self):
        state = self.app.dashboard.state()
        self.addCleanup(state.close)
        payload = {'title': 'CVE test', 'severity': 'critical'}
        channels = [{'id': 'local', 'type': 'console'}]
        self.assertTrue(state.event('news', 'cve', payload, channels))
        self.assertFalse(state.event('news', 'cve', payload, channels))
        with self.assertRaises(Exception):
            state.event('news', 'rollback', payload, channels * 2)
        self.assertIsNone(state.get('event:news:rollback'))
        self.assertEqual(state.db.execute('SELECT count(*) FROM events').fetchone()[0], 1)
        with patch('builtins.print'):
            self.assertEqual(deliver(state, {'notifications': channels}, None), 0)
        self.assertEqual(state.db.execute('SELECT count(*) FROM deliveries WHERE delivered IS NULL').fetchone()[0], 0)

    def test_real_scan_and_preview_isolation(self):
        dashboard = self.app.dashboard
        config = dashboard.config()
        def bot(state, config, http):
            state.event('news', 'scan', {'title': 'Scan', 'severity': 'medium'}, config['notifications'])
            return []
        with patch.dict('jyoticve.cli.BOTS', {'news': bot}), patch('builtins.print'):
            self.assertTrue(run('news', config, dry_run=True))
            self.assertEqual(dashboard.snapshot()['runs'], [])
            self.assertEqual(dashboard.snapshot()['events'], [])
            self.assertTrue(run('news', config))
        data = dashboard.snapshot()
        self.assertEqual(data['runs'][0]['status'], 'success')
        self.assertEqual(len(data['events']), 1)
        self.assertGreater(data['next_due']['news'], 0)

    def test_cross_connection_locks_and_subprocess_configuration(self):
        with lock('postgres:state.scheduler.lock'):
            self.assertTrue(self.app.dashboard.external_scheduler())
            with self.assertRaises(RuntimeError):
                with lock('postgres:state.scheduler.lock'):
                    pass
        self.assertFalse(self.app.dashboard.external_scheduler())
        result = subprocess.run([sys.executable, '-m', 'jyoticve', '--config', 'postgres:config', 'validate'],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Configuration valid', result.stdout)

    def test_invalid_edit_does_not_replace_saved_document(self):
        dashboard = self.app.dashboard
        before = dashboard.config()['certificate_thresholds']
        with self.assertRaises(ValueError):
            dashboard.save('settings', {'certificate_thresholds': [-1]})
        self.assertEqual(dashboard.config()['certificate_thresholds'], before)

    def test_render_start_command_and_scheduler(self):
        import requests
        # Exercise the real Gunicorn command and scheduler process while keeping
        # network scans and notification delivery disabled in this test schema.
        self.app.dashboard.save('settings', {'schedules': {
            bot: {'enabled': False, 'interval_seconds': 60}
            for bot in ('news', 'certificates', 'stack')}})
        self.app.dashboard.close()
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            port = listener.getsockname()[1]
        with tempfile.TemporaryFile() as log:
            process = subprocess.Popen([sys.executable, '-m', 'gunicorn', '--config',
                'deploy/gunicorn.conf.py', 'jyoticve.hosted:create_app()'],
                env=dict(os.environ, PORT=str(port)), stdout=log, stderr=log)
            try:
                deadline = time.monotonic() + 45
                ready = False
                while time.monotonic() < deadline and process.poll() is None:
                    try:
                        response = requests.get(f'http://127.0.0.1:{port}/api/state',
                            headers={'Host': 'monitor.example.com'},
                            auth=('admin', 'test-password-at-least-24-characters'), timeout=15)
                        ready = response.status_code == 200 and response.json()['scheduler'] == 'running'
                        if ready:
                            break
                    except requests.RequestException:
                        pass
                    time.sleep(0.5)
                self.assertTrue(ready, 'Gunicorn did not serve authenticated state with a running scheduler')
                self.assertEqual(requests.get(f'http://127.0.0.1:{port}/healthz', timeout=15).json(), {'status': 'ok'})
            finally:
                process.terminate()
                try:
                    process.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
