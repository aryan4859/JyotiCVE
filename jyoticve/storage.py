"""PostgreSQL connections and durable dashboard documents.

Virtual postgres: paths contain no credentials; subprocesses read DATABASE_URL
from their inherited environment. SQLite remains available for local use.
"""
from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import re
from urllib.parse import urlsplit, urlunsplit


def is_postgres(path):
    return str(path).startswith('postgres:')


def connection_url(url=None):
    url = (url if url is not None else os.environ.get('DATABASE_DIRECT_URL') or os.environ.get('DATABASE_URL', '')).strip()
    if not url.startswith(('postgresql://', 'postgres://')):
        raise ValueError('DATABASE_URL must be a PostgreSQL connection URL (postgresql://USER:PASSWORD@HOST/DATABASE)')
    parsed = urlsplit(url)
    # Prisma uses the same credentials for its documented direct endpoint.
    # Our long-lived scheduler locks require session continuity.
    if parsed.hostname == 'pooled.db.prisma.io':
        authority = parsed.netloc.rsplit('@', 1)
        authority[-1] = authority[-1].replace('pooled.db.prisma.io', 'db.prisma.io', 1)
        url = urlunsplit(parsed._replace(netloc='@'.join(authority)))
    return url


def connect():
    import psycopg
    url = connection_url()
    try:
        return psycopg.connect(url, autocommit=True, connect_timeout=15, prepare_threshold=None)
    except psycopg.Error:
        raise RuntimeError('Unable to connect to PostgreSQL. Check DATABASE_URL, database availability, network access, and SSL settings.') from None


class PostgresDB:
    """Execute the application's small shared SQL vocabulary on PostgreSQL."""
    def __init__(self):
        self.connection = connect()

    def execute(self, query, args=()):
        query = query.replace('?', '%s')
        query = re.sub(r"json_extract\((\w+(?:\.\w+)?),'\$\.severity'\)",
                       r"(\1::jsonb ->> 'severity')", query)
        cursor = self.connection.execute(query, args or None)
        return cursor

    def commit(self):
        self.connection.commit()

    def close(self):
        self.connection.close()

    def __enter__(self):
        self.transaction = self.connection.transaction()
        self.transaction.__enter__()
        return self

    def __exit__(self, *args):
        return self.transaction.__exit__(*args)


def initialize(db):
    # Serialize first-time schema creation across workers and deployments.
    with db:
        db.execute('SELECT pg_advisory_xact_lock(734952001)')
        for statement in (
            'CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT NOT NULL)',
            'CREATE TABLE IF NOT EXISTS events (id BIGSERIAL PRIMARY KEY, bot TEXT, identity TEXT, fingerprint TEXT, payload TEXT, created TEXT)',
            'CREATE TABLE IF NOT EXISTS deliveries (event_id BIGINT, channel TEXT, delivered TEXT, attempts INTEGER DEFAULT 0, parts_sent INTEGER DEFAULT 0, PRIMARY KEY(event_id, channel))',
            'CREATE TABLE IF NOT EXISTS runs (id BIGSERIAL PRIMARY KEY, bot TEXT, started TEXT, finished TEXT, status TEXT, detail TEXT)',
            'CREATE TABLE IF NOT EXISTS documents (key TEXT PRIMARY KEY, value TEXT NOT NULL)',
        ):
            db.execute(statement)


def read_text(path):
    if not is_postgres(path):
        return Path(path).read_text()
    with connect() as db:
        row = db.execute('SELECT value FROM documents WHERE key=%s', (str(path),)).fetchone()
    if row is None:
        raise ValueError('PostgreSQL workspace has not been initialized')
    return row[0]


def write_document(path, value):
    with connect() as db:
        db.execute('INSERT INTO documents(key,value) VALUES(%s,%s) ON CONFLICT(key) DO UPDATE SET value=excluded.value',
                   (str(path), value))


def lock_key(path):
    return int.from_bytes(hashlib.sha256(('jyoticve:' + str(path)).encode()).digest()[:8], 'big', signed=True)


@contextmanager
def database_lock(path):
    # Use a direct or session-pooled URL, not a transaction-pooling endpoint.
    with connect() as db:
        schema = db.execute('SELECT current_schema()').fetchone()[0]
        key = lock_key(str(schema) + ':' + str(path))
        if not db.execute('SELECT pg_try_advisory_lock(%s)', (key,)).fetchone()[0]:
            raise RuntimeError('This bot or dashboard is already running against this database')
        try:
            yield
        finally:
            db.execute('SELECT pg_advisory_unlock(%s)', (key,))
