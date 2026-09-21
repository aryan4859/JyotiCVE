"""Configuration, durable state/outbox, HTTP retries, and notifications."""
import hashlib
import json
import logging
import os
import sqlite3
import time
import threading
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from urllib.parse import urlsplit

import requests

LOG = logging.getLogger('jyoticve')
NVD_LOCK = threading.Lock()
NVD_LAST = 0.0


def now():
    return datetime.now(timezone.utc)


def stamp():
    return now().isoformat()


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def load_config(path):
    path = Path(path).resolve()
    config = json.loads(path.read_text())
    config['_base'] = str(path.parent)
    for key in ('state_file', 'domains_file', 'inventory_file'):
        config[key] = str(path.parent / config.get(key, {
            'state_file': 'state/monitor.sqlite3', 'domains_file': 'domains.txt',
            'inventory_file': 'inventory.json'}[key]))
    thresholds = config.get('certificate_thresholds', [30, 14, 7, 3])
    if not thresholds or any(type(n) is not int or n <= 0 for n in thresholds):
        raise ValueError('certificate_thresholds must be positive integers')
    config['certificate_thresholds'] = sorted(set(thresholds), reverse=True)
    for bot in ('news', 'certificates', 'stack'):
        interval = config.get('schedules', {}).get(bot, {}).get('interval_seconds',
                                                               {'news': 900, 'certificates': 86400, 'stack': 21600}[bot])
        if type(interval) not in (int, float) or interval < 1:
            raise ValueError(f'Invalid interval for {bot}')
    if config.get('initial_lookback_hours', 24) <= 0:
        raise ValueError('initial_lookback_hours must be positive')
    for field in ('http_timeout_seconds', 'tls_timeout_seconds', 'certificate_critical_days'):
        if field in config and (type(config[field]) not in (int, float) or config[field] <= 0):
            raise ValueError(f'{field} must be a positive number')
    for field in ('news_keywords', 'significant_news_terms'):
        if field in config and (not isinstance(config[field], list) or not all(
                isinstance(word, str) and word.strip() for word in config[field])):
            raise ValueError(f'{field} must be an array of nonempty strings')
    channels = config.get('notifications', [])
    if not isinstance(channels, list) or not channels:
        raise ValueError('Configure at least one notification channel (console is available for local use)')
    ids = [c['id'] for c in channels]
    if len(ids) != len(set(ids)):
        raise ValueError('Notification channel IDs must be unique')
    for channel in channels:
        if channel.get('type') not in ('console', 'webhook', 'slack', 'teams'):
            raise ValueError('Supported notification types: console, webhook, slack, teams')
        if channel['type'] != 'console':
            url = os.getenv(channel.get('url_env', ''), '')
            if urlsplit(url).scheme != 'https' or not urlsplit(url).hostname:
                raise ValueError(f"Set HTTPS destination environment variable for {channel['id']}")
    return config


class HTTP:
    def __init__(self, timeout=30):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers['User-Agent'] = 'JyotiCVE/1.0'

    def get(self, url, **kwargs):
        return self.request('GET', url, **kwargs)

    def request(self, method, url, **kwargs):
        global NVD_LAST
        for attempt in range(4):
            try:
                if 'services.nvd.nist.gov/' in url:
                    with NVD_LOCK:
                        delay = (0.7 if os.getenv('NVD_API_KEY') else 6.1) - (time.monotonic() - NVD_LAST)
                        if delay > 0:
                            time.sleep(delay)
                        NVD_LAST = time.monotonic()
                response = self.session.request(method, url, timeout=self.timeout, **kwargs)
                if response.status_code == 429 or response.status_code >= 500:
                    delay = min(60, 2 ** (attempt + 1))
                    retry = response.headers.get('Retry-After')
                    if retry:
                        try:
                            delay = float(retry)
                        except ValueError:
                            try:
                                delay = (parsedate_to_datetime(retry) - now()).total_seconds()
                            except (ValueError, TypeError):
                                pass
                    if attempt < 3:
                        time.sleep(max(0, min(delay, 300)))
                        continue
                response.raise_for_status()
                if not 200 <= response.status_code < 300:
                    raise ValueError('Unexpected HTTP response')
                if method == 'GET':
                    data = response.json()
                    if not isinstance(data, dict):
                        raise ValueError('Expected JSON object')
                    return data
                return response
            except (requests.RequestException, ValueError):
                if attempt == 3:
                    # Do not log exception URLs: notification URLs often contain secrets.
                    raise RuntimeError('HTTP request failed after retries') from None
                time.sleep(2 ** attempt)


class State:
    def __init__(self, path):
        if str(path) != ':memory:':
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path, timeout=30)
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.executescript('''
        CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS events (
          id INTEGER PRIMARY KEY, bot TEXT, identity TEXT, fingerprint TEXT, payload TEXT, created TEXT);
        CREATE TABLE IF NOT EXISTS deliveries (
          event_id INTEGER, channel TEXT, delivered TEXT, attempts INTEGER DEFAULT 0, parts_sent INTEGER DEFAULT 0,
          PRIMARY KEY(event_id, channel));
        CREATE TABLE IF NOT EXISTS runs (
          id INTEGER PRIMARY KEY, bot TEXT, started TEXT, finished TEXT, status TEXT, detail TEXT);
        ''')
        if 'parts_sent' not in {row[1] for row in self.db.execute('PRAGMA table_info(deliveries)')}:
            self.db.execute('ALTER TABLE deliveries ADD COLUMN parts_sent INTEGER DEFAULT 0')
        self.db.commit()

    def get(self, key, default=None):
        row = self.db.execute('SELECT value FROM kv WHERE key=?', (key,)).fetchone()
        return json.loads(row[0]) if row else default

    def put(self, key, value):
        self.db.execute('INSERT OR REPLACE INTO kv VALUES (?,?)', (key, json.dumps(value)))
        self.db.commit()

    def event(self, bot, identity, payload, channels, meaningful=None):
        digest = fingerprint(payload if meaningful is None else meaningful)
        key = f'event:{bot}:{identity}'
        if self.get(key) == digest:
            return False
        with self.db:
            cursor = self.db.execute('INSERT INTO events(bot,identity,fingerprint,payload,created) VALUES(?,?,?,?,?)',
                                     (bot, identity, digest, json.dumps(payload), stamp()))
            for channel in channels:
                self.db.execute('INSERT INTO deliveries(event_id,channel) VALUES(?,?)', (cursor.lastrowid, channel['id']))
            self.db.execute('INSERT OR REPLACE INTO kv VALUES (?,?)', (key, json.dumps(digest)))
        return True

    def close(self):
        self.db.close()


def render(payload):
    return '\n'.join([f"[{payload.get('severity', 'informational').upper()}] {payload.get('title', '')}",
                      payload.get('summary', ''), json.dumps(payload.get('details', {}), indent=2, ensure_ascii=False)])


def deliver(state, config, http, bot=None):
    channels = {c['id']: c for c in config['notifications']}
    query = '''SELECT e.id,d.channel,e.payload,d.parts_sent FROM events e JOIN deliveries d ON e.id=d.event_id
               WHERE d.delivered IS NULL'''
    args = ()
    if bot:
        query += ' AND e.bot=?'
        args = (bot,)
    query += " ORDER BY CASE json_extract(e.payload,'$.severity') WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,e.id"
    failures = 0
    for event_id, channel_id, raw, parts_sent in state.db.execute(query, args).fetchall():
        try:
            channel = channels[channel_id]
            payload = json.loads(raw)
            message = render(payload)
            kind = channel['type']
            if kind == 'console':
                print(message, flush=True)
            else:
                url = os.environ[channel['url_env']]
                chunks = [message[i:i + 6000] for i in range(0, len(message), 6000)] if kind != 'webhook' else [message]
                for index in range(parts_sent, len(chunks)):
                    body = payload | {'event_id': event_id} if kind == 'webhook' else {'text': chunks[index]}
                    if kind == 'teams':
                        body = {'type': 'message', 'attachments': [{
                            'contentType': 'application/vnd.microsoft.card.adaptive',
                            'content': {'type': 'AdaptiveCard', 'version': '1.2',
                                        'body': [{'type': 'TextBlock', 'text': chunks[index], 'wrap': True}]}}]}
                    http.request('POST', url, json=body,
                                 headers={'Idempotency-Key': f'jyoticve-{event_id}-{channel_id}-{index}'}, allow_redirects=False)
                    state.db.execute('UPDATE deliveries SET parts_sent=? WHERE event_id=? AND channel=?',
                                     (index + 1, event_id, channel_id))
                    state.db.commit()
            state.db.execute('UPDATE deliveries SET delivered=?,attempts=attempts+1 WHERE event_id=? AND channel=?',
                             (stamp(), event_id, channel_id))
        except (RuntimeError, KeyError):
            failures += 1
            state.db.execute('UPDATE deliveries SET attempts=attempts+1 WHERE event_id=? AND channel=?',
                             (event_id, channel_id))
            LOG.error('Delivery failed event=%s channel=%s; retained for retry', event_id, channel_id)
        state.db.commit()
    return failures
