"""Local dashboard server. No additional dependencies or frontend build required."""
import json
import fcntl
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from .certificates import domains
from .core import State, load_config, stamp
from .matching import inventory

BOTS = ('news', 'certificates', 'stack')
STATIC = Path(__file__).parent / 'static'


def atomic_write(path, text, validator):
    path = Path(path)
    fd, name = tempfile.mkstemp(prefix='.dashboard-', suffix=path.suffix, dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as handle:
            handle.write(text)
        validator(name)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


class Dashboard:
    def __init__(self, config_path):
        self.path = Path(config_path).resolve()
        self.token = secrets.token_urlsafe(32)
        self.mutex = threading.RLock()
        self.jobs = {}
        self.scheduler = None
        self.scheduler_log = None
        self.scheduler_stopping = False
        self.scheduler_error = ''
        self.config()  # Fail before binding if configuration is invalid.

    def config(self):
        return load_config(self.path)

    def state(self):
        return State(self.config()['state_file'])

    def snapshot(self):
        config = self.config()
        state = self.state()
        try:
            state.db.row_factory = __import__('sqlite3').Row
            events = [dict(r) for r in state.db.execute('SELECT id,bot,created,payload FROM events ORDER BY id DESC LIMIT 200')]
            for event in events:
                event['payload'] = json.loads(event['payload'])
                event['payload'].pop('details', None)
            runs = [dict(r) for r in state.db.execute('SELECT * FROM runs ORDER BY id DESC LIMIT 100')]
            counts = dict(state.db.execute("SELECT coalesce(json_extract(payload,'$.severity'),'informational'),count(*) FROM events GROUP BY 1").fetchall())
            pending = state.db.execute('SELECT count(*) FROM deliveries WHERE delivered IS NULL').fetchone()[0]
            certificates = [json.loads(r[0]) for r in state.db.execute("SELECT value FROM kv WHERE key LIKE 'certificates:status:%'")]
            due = {bot: state.get(f'{bot}:next_due') for bot in BOTS}
        finally:
            state.close()
        with self.mutex:
            scheduler = 'stopped'
            if self.scheduler is not None:
                if self.scheduler.poll() is None:
                    scheduler = 'stopping' if self.scheduler_stopping else 'running'
                else:
                    size = os.fstat(self.scheduler_log.fileno()).st_size
                    self.scheduler_error = (os.pread(self.scheduler_log.fileno(), 4000, max(0, size - 4000)).decode(errors='replace')
                                            if self.scheduler.returncode else '')
                    self.scheduler_log.close()
                    self.scheduler_log = None
                    self.scheduler = None
                    self.scheduler_stopping = False
            if scheduler == 'stopped' and self.external_scheduler():
                scheduler = 'external'
            jobs = []
            for job in self.jobs.values():
                public = {k: v for k, v in job.items() if k not in ('process', 'log')}
                if job['status'] == 'running':
                    # pread does not move the child's shared output file offset.
                    size = os.fstat(job['log'].fileno()).st_size
                    public['output'] = os.pread(job['log'].fileno(), 32000, max(0, size - 32000)).decode(errors='replace')
                jobs.append(public)
        return {'timestamp': stamp(), 'events': events, 'runs': runs, 'counts': counts,
                'pending': pending, 'certificates': certificates, 'next_due': due,
                'domains': Path(config['domains_file']).read_text(), 'inventory': inventory(config['inventory_file']),
                'settings': {k: config.get(k) for k in ('schedules', 'certificate_thresholds', 'certificate_critical_days',
                                                       'initial_lookback_hours', 'news_keywords', 'notifications')},
                'scheduler': scheduler, 'scheduler_message': self.scheduler_error,
                'jobs': list(reversed(jobs)), 'nvd_key_set': bool(os.getenv('NVD_API_KEY'))}

    def external_scheduler(self):
        path = Path(self.config()['state_file'] + '.scheduler.lock')
        if not path.exists():
            return False
        with path.open() as handle:
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return True
            fcntl.flock(handle, fcntl.LOCK_UN)
        return False

    def event(self, identifier):
        state = self.state()
        try:
            row = state.db.execute('SELECT id,bot,created,payload FROM events WHERE id=?', (identifier,)).fetchone()
            if row is None:
                return None
            return {'id': row[0], 'bot': row[1], 'created': row[2], 'payload': json.loads(row[3])}
        finally:
            state.close()

    def save(self, kind, body):
        with self.mutex:
            config = self.config()
            if kind == 'domains':
                value = body['domains']
                if not isinstance(value, str):
                    raise ValueError('Domains must be text, one hostname per line')
                atomic_write(config['domains_file'], value, domains)
            elif kind == 'inventory':
                value = body['inventory']
                atomic_write(config['inventory_file'], json.dumps(value, indent=2) + '\n', inventory)
            elif kind == 'settings':
                allowed = {'schedules', 'certificate_thresholds', 'certificate_critical_days',
                           'initial_lookback_hours', 'news_keywords', 'notifications'}
                if set(body) - allowed:
                    raise ValueError('Unsupported settings field')
                if 'schedules' in body:
                    if not isinstance(body['schedules'], dict) or set(body['schedules']) != set(BOTS):
                        raise ValueError('Provide a schedule for each of the three bots')
                    for schedule in body['schedules'].values():
                        if type(schedule.get('enabled')) is not bool:
                            raise ValueError('Schedule enabled must be true or false')
                raw = json.loads(self.path.read_text())
                old_schedules = raw.get('schedules', {})
                raw.update(body)
                atomic_write(self.path, json.dumps(raw, indent=2) + '\n', load_config)
                state = self.state()
                try:
                    for bot in BOTS:
                        before = old_schedules.get(bot, {})
                        after = raw.get('schedules', {}).get(bot, {})
                        if before != after:
                            # Make schedule changes effective on the next scheduler tick.
                            state.put(f'{bot}:next_due', 0)
                finally:
                    state.close()
            else:
                raise ValueError('Unknown configuration section')
        return {'message': 'Saved successfully'}

    def scan(self, body):
        bot, preview = body.get('bot'), body.get('preview', True)
        if bot not in BOTS or type(preview) is not bool:
            raise ValueError('Choose a valid bot and scan mode')
        with self.mutex:
            if any(j['bot'] == bot and j['status'] == 'running' for j in self.jobs.values()):
                raise ValueError('A scan for this bot is already running')
            while len(self.jobs) >= 30:
                completed = next((key for key, job in self.jobs.items() if job['status'] != 'running'), None)
                if completed is None:
                    raise ValueError('Scan queue is full')
                del self.jobs[completed]
            identifier = secrets.token_hex(8)
            log = tempfile.TemporaryFile()
            command = [sys.executable, '-u', '-m', 'jyoticve', '--config', str(self.path), 'run', bot]
            if preview:
                command.append('--dry-run')
            process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
            job = {'id': identifier, 'bot': bot, 'preview': preview, 'status': 'running',
                   'started': stamp(), 'output': '', 'process': process, 'log': log}
            self.jobs[identifier] = job
            threading.Thread(target=self._finish, args=(job,), daemon=True).start()
            return {'message': 'Preview started' if preview else 'Scan started', 'job_id': identifier}

    def _finish(self, job):
        code = job['process'].wait()
        with self.mutex:
            job['status'] = 'success' if code == 0 else 'failed'
            job['finished'] = stamp()
            size = os.fstat(job['log'].fileno()).st_size
            job['output'] = os.pread(job['log'].fileno(), 32000, max(0, size - 32000)).decode(errors='replace')
            job['log'].close()
            job.pop('log')
            job.pop('process')

    def scheduling(self, enabled):
        with self.mutex:
            if enabled:
                if self.scheduler and self.scheduler.poll() is None:
                    return {'message': 'Scheduler is already active'}
                if self.external_scheduler():
                    raise ValueError('Scheduler is already running in another terminal or service. Manage it there, or stop it before starting it here.')
                if self.scheduler_log:
                    self.scheduler_log.close()
                self.scheduler_log = tempfile.TemporaryFile()
                self.scheduler_stopping = False
                self.scheduler_error = ''
                self.scheduler = subprocess.Popen([sys.executable, '-u', '-m', 'jyoticve', '--config', str(self.path), 'serve'],
                                                   stdout=self.scheduler_log, stderr=subprocess.STDOUT)
                return {'message': 'Scheduler starting'}
            if self.scheduler and self.scheduler.poll() is None:
                self.scheduler.terminate()
                self.scheduler_stopping = True
            return {'message': 'Scheduler stopping; active scans will finish'}

    def close(self):
        self.scheduling(False)
        # Manually triggered scans are allowed to finish, just like CLI scans.


class Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, dashboard):
        self.dashboard = dashboard
        super().__init__(address, Handler)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def reply(self, status, data, content_type='application/json'):
        raw = json.dumps(data).encode() if content_type == 'application/json' else data
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(raw)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        self.end_headers()
        self.wfile.write(raw)

    def allowed_host(self):
        port = self.server.server_port
        return self.headers.get('Host') in (f'localhost:{port}', f'127.0.0.1:{port}')

    def do_GET(self):
        if not self.allowed_host():
            return self.reply(403, {'error': 'Use the local dashboard address'})
        path = urlsplit(self.path).path
        try:
            if path == '/api/state':
                return self.reply(200, self.server.dashboard.snapshot())
            if path.startswith('/api/events/') and path.rsplit('/', 1)[1].isdigit():
                event = self.server.dashboard.event(int(path.rsplit('/', 1)[1]))
                return self.reply(200, event) if event else self.reply(404, {'error': 'Event not found'})
            if path == '/api/session':
                return self.reply(200, {'token': self.server.dashboard.token})
            assets = {'/': ('index.html', 'text/html; charset=utf-8'),
                      '/app.js': ('app.js', 'text/javascript; charset=utf-8'),
                      '/style.css': ('style.css', 'text/css; charset=utf-8')}
            if path in assets:
                name, mime = assets[path]
                return self.reply(200, (STATIC / name).read_bytes(), mime)
            return self.reply(404, {'error': 'Not found'})
        except Exception:
            return self.reply(500, {'error': 'Unable to load dashboard data; check configuration and file permissions'})

    def do_POST(self):
        if not self.allowed_host() or self.headers.get('X-Dashboard-Token') != self.server.dashboard.token:
            return self.reply(403, {'error': 'Refresh the local dashboard to continue'})
        origin = self.headers.get('Origin')
        if origin and origin != 'http://' + self.headers.get('Host', ''):
            return self.reply(403, {'error': 'Cross-origin requests are not allowed'})
        try:
            if self.headers.get('Content-Type') != 'application/json':
                raise ValueError('Expected application/json')
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 < length <= 262144:
                raise ValueError('Request must be between 1 byte and 256 KB')
            body = json.loads(self.rfile.read(length))
            if not isinstance(body, dict):
                raise ValueError('Expected a JSON object')
            path = urlsplit(self.path).path
            if path == '/api/scan':
                result = self.server.dashboard.scan(body)
            elif path == '/api/scheduler':
                if type(body.get('enabled')) is not bool:
                    raise ValueError('enabled must be true or false')
                result = self.server.dashboard.scheduling(body['enabled'])
            elif path in ('/api/domains', '/api/inventory', '/api/settings'):
                result = self.server.dashboard.save(path.rsplit('/', 1)[1], body)
            else:
                return self.reply(404, {'error': 'Not found'})
            return self.reply(200, result)
        except (ValueError, KeyError, TypeError, AttributeError) as error:
            return self.reply(400, {'error': str(error)})
        except Exception:
            return self.reply(500, {'error': 'Operation failed; check configuration and file permissions'})


def serve_web(config_path, port=8080):
    dashboard = Dashboard(config_path)
    server = Server(('127.0.0.1', port), dashboard)
    print(f'JyotiCVE dashboard: http://127.0.0.1:{server.server_port}', flush=True)
    print('Use Start monitoring in the dashboard to enable scheduled scans.', flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        dashboard.close()
        server.server_close()
