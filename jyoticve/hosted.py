"""Authenticated single-instance WSGI deployment with persistent state and supervision."""
import hashlib
import json
import logging
import os
from pathlib import Path
import secrets
import subprocess
import threading
import time
from urllib.parse import urlsplit

from flask import Flask, jsonify, request, send_from_directory
from werkzeug.exceptions import HTTPException

from .cli import lock
from .core import load_config
from .web import Dashboard, STATIC

LOG = logging.getLogger('jyoticve.hosted')


def create_once(path, content):
    """Never overwrite an operator's configuration during a redeploy."""
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open('x') as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        path.chmod(0o600)
    except FileExistsError:
        pass


def bootstrap(data_dir):
    root = Path(data_dir)
    if not root.is_absolute():
        raise ValueError('JYOTICVE_DATA_DIR must be an absolute persistent directory')
    root = root.resolve()
    root.mkdir(parents=True, exist_ok=True)
    with lock(str(root / 'bootstrap.lock')):
        path = root / 'config.json'
        create_once(path, (Path(__file__).parent / 'default-config.json').read_text())
        config = load_config(path)
        for key in ('state_file', 'domains_file', 'inventory_file'):
            if not Path(config[key]).resolve().is_relative_to(root):
                raise ValueError(f'{key} must remain inside JYOTICVE_DATA_DIR')
        create_once(Path(config['domains_file']), '# Add monitored hostnames in the dashboard.\n')
        create_once(Path(config['inventory_file']), '[]\n')
    return path


class ManagedDashboard(Dashboard):
    """One scheduler per deployment. Pause preference survives worker restarts."""
    def __init__(self, path, start_monitor=True):
        super().__init__(path)
        self.scheduler_output_to_console = True
        self.stop_monitor = threading.Event()
        self.monitor = None
        self.closed = False
        self.instance_lock = lock(self.config()['state_file'] + '.hosted.lock')
        self.instance_lock.__enter__()
        state = self.state()
        try:
            self.scheduler_wanted = state.get('hosted:scheduler_enabled', True)
            if state.get('hosted:scheduler_enabled') is None:
                state.put('hosted:scheduler_enabled', self.scheduler_wanted)
        finally:
            state.close()
        if start_monitor:
            self.monitor = threading.Thread(target=self._supervise, name='scheduler-supervisor', daemon=True)
            self.monitor.start()

    def supervisor_tick(self):
        with self.mutex:
            if self.closed or not self.scheduler_wanted:
                return
            if self.scheduler and self.scheduler.poll() is None:
                return
            LOG.info('Starting managed scheduler')
            super().scheduling(True)

    def _supervise(self):
        while not self.stop_monitor.is_set():
            try:
                self.supervisor_tick()
            except Exception as error:
                LOG.error('Scheduler supervision failed (%s); retrying', type(error).__name__)
            self.stop_monitor.wait(5)

    def scheduling(self, enabled):
        with self.mutex:
            if self.closed:
                raise ValueError('Service is shutting down')
            state = self.state()
            try:
                state.put('hosted:scheduler_enabled', enabled)
            finally:
                state.close()
            self.scheduler_wanted = enabled
            return super().scheduling(enabled)

    def close(self):
        with self.mutex:
            if self.closed:
                return
            self.closed = True
            self.stop_monitor.set()
            children = [job['process'] for job in self.jobs.values() if job.get('process')]
            if self.scheduler:
                children.append(self.scheduler)
        # Preserve the operator's pause/start preference; shutdown is not a user pause.
        for process in children:
            if process.poll() is None:
                process.terminate()
        deadline = time.monotonic() + 20
        for process in children:
            try:
                process.wait(timeout=max(0, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        if self.monitor:
            self.monitor.join(timeout=2)
        if self.scheduler_log:
            self.scheduler_log.close()
        self.instance_lock.__exit__(None, None, None)


def settings_from_environment(env):
    username = env.get('JYOTICVE_ADMIN_USER', 'admin')
    password = env.get('JYOTICVE_ADMIN_PASSWORD', '')
    if not username or ':' in username or len(password) < 24:
        raise ValueError('Set JYOTICVE_ADMIN_PASSWORD to at least 24 characters and a valid JYOTICVE_ADMIN_USER')
    origin = env.get('JYOTICVE_PUBLIC_ORIGIN') or env.get('RENDER_EXTERNAL_URL', '')
    parsed = urlsplit(origin)
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or
            parsed.path not in ('', '/') or parsed.query or parsed.fragment):
        raise ValueError('Set JYOTICVE_PUBLIC_ORIGIN or RENDER_EXTERNAL_URL to the public HTTPS origin')
    data_dir = env.get('JYOTICVE_DATA_DIR', '')
    if not data_dir or not Path(data_dir).is_absolute():
        raise ValueError('Set JYOTICVE_DATA_DIR to an absolute persistent directory')
    return username, password, origin.rstrip('/'), data_dir


def create_app(env=None, start_monitor=True):
    username, password, origin, data_dir = settings_from_environment(os.environ if env is None else env)
    dashboard = ManagedDashboard(bootstrap(data_dir), start_monitor=start_monitor)
    app = Flask(__name__, static_folder=None)
    app.config['MAX_CONTENT_LENGTH'] = 262144
    app.dashboard = dashboard
    expected_host = urlsplit(origin).netloc.lower()
    expected_auth = hashlib.sha256((username + ':' + password).encode()).digest()

    @app.before_request
    def protect():
        if request.path == '/healthz' and request.method == 'GET':
            return None
        if request.host.lower() != expected_host:
            return jsonify(error='Unexpected host'), 403
        auth = request.authorization
        supplied = ''
        if auth and auth.type == 'basic':
            supplied = (auth.username or '') + ':' + (auth.password or '')
        if not secrets.compare_digest(hashlib.sha256(supplied.encode()).digest(), expected_auth):
            return jsonify(error='Dashboard sign-in required'), 401, {'WWW-Authenticate': 'Basic realm="JyotiCVE", charset="UTF-8"'}
        if request.method not in ('GET', 'HEAD', 'OPTIONS'):
            supplied_token = request.headers.get('X-Dashboard-Token', '')
            if not secrets.compare_digest(supplied_token.encode(), dashboard.token.encode()):
                return jsonify(error='Refresh the dashboard to continue'), 403
            # Require the configured HTTPS origin, never a client-supplied forwarded host.
            if request.headers.get('Origin') != origin:
                return jsonify(error='Cross-origin requests are not allowed'), 403

    @app.after_request
    def security_headers(response):
        response.headers.update({
            'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY',
            'Strict-Transport-Security': 'max-age=31536000', 'Referrer-Policy': 'no-referrer',
            'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"})
        return response

    @app.errorhandler(Exception)
    def error_response(error):
        if isinstance(error, HTTPException):
            return jsonify(error=error.name), error.code
        if isinstance(error, (ValueError, KeyError, TypeError, AttributeError)):
            return jsonify(error=str(error)), 400
        LOG.error('Dashboard request failed (%s)', type(error).__name__)
        return jsonify(error='Operation failed; check the service logs and configuration'), 500

    @app.get('/healthz')
    def health():
        # A source outage must not cause service restart loops. Verify the local runtime only.
        if dashboard.closed or (dashboard.monitor and not dashboard.monitor.is_alive()):
            return jsonify(status='unavailable'), 503
        try:
            state = dashboard.state()
            try:
                state.db.execute('SELECT 1').fetchone()
            finally:
                state.close()
        except Exception:
            return jsonify(status='unavailable'), 503
        return jsonify(status='ok')

    @app.get('/')
    def index():
        return send_from_directory(STATIC, 'index.html')

    @app.get('/<asset>')
    def static_asset(asset):
        if asset not in ('app.js', 'style.css'):
            return jsonify(error='Not found'), 404
        return send_from_directory(STATIC, asset)

    @app.get('/api/session')
    def session():
        return jsonify(token=dashboard.token)

    @app.get('/api/state')
    def workspace():
        return jsonify(dashboard.snapshot())

    @app.get('/api/events/<int:identifier>')
    def event(identifier):
        result = dashboard.event(identifier)
        return jsonify(result) if result else (jsonify(error='Event not found'), 404)

    @app.post('/api/<action>')
    def mutate(action):
        if not request.is_json:
            return jsonify(error='Expected application/json'), 400
        body = request.get_json()
        if not isinstance(body, dict):
            raise ValueError('Expected a JSON object')
        if action == 'scan':
            result = dashboard.scan(body)
        elif action == 'scheduler':
            if type(body.get('enabled')) is not bool:
                raise ValueError('enabled must be true or false')
            result = dashboard.scheduling(body['enabled'])
        elif action in ('domains', 'inventory', 'settings'):
            result = dashboard.save(action, body)
        else:
            return jsonify(error='Not found'), 404
        return jsonify(result)

    return app
