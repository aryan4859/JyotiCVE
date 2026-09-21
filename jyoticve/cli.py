"""Command-line entry point and persistent independent schedules."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import fcntl
import json
import logging
from pathlib import Path
import signal
import sqlite3
import threading
import time

from .bots import BOTS
from .certificates import domains
from .core import HTTP, LOG, State, deliver, load_config, stamp
from .matching import inventory


@contextmanager
def lock(path):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, 'a') as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError('This bot is already running against this state database') from None
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def run(bot, config, dry_run=False):
    with lock(config['state_file'] + '.' + bot + '.lock'):
        state = State(':memory:' if dry_run else config['state_file'])
        if dry_run:
            if Path(config['state_file']).exists():
                source = sqlite3.connect(f"file:{config['state_file']}?mode=ro", uri=True)
                source.backup(state.db)
                source.close()
            config = dict(config, notifications=[{'id': 'preview', 'type': 'console'}])
        http = HTTP(config.get('http_timeout_seconds', 30))
        record = state.db.execute('INSERT INTO runs(bot,started,status) VALUES(?,?,?)', (bot, stamp(), 'running')).lastrowid
        state.db.commit()
        LOG.info('Execution started bot=%s dry_run=%s', bot, dry_run)
        errors = []
        try:
            errors = BOTS[bot](state, config, http)
        except Exception as error:
            errors = [f'Workflow failed ({type(error).__name__}); inspect configuration and source availability']
            LOG.error('%s', errors[0])
        if errors:
            state.event(bot, 'workflow-health', {'title': f'{bot} monitoring incomplete', 'severity': 'high',
                                               'kind': 'operational', 'summary': '; '.join(errors), 'details': {}},
                        config['notifications'])
        elif state.get(f'{bot}:unhealthy'):
            state.event(bot, 'workflow-health', {'title': f'{bot} monitoring recovered', 'severity': 'informational',
                                               'kind': 'recovery', 'summary': 'Collection completed successfully.', 'details': {}},
                        config['notifications'])
        state.put(f'{bot}:unhealthy', bool(errors))
        if dry_run:
            # Only display new preview deliveries, never retry real destinations in a dry run.
            state.db.execute("DELETE FROM deliveries WHERE channel != 'preview'")
            state.db.commit()
        failed = deliver(state, config, http, bot)
        if failed:
            errors.append(f'{failed} notification deliveries pending retry')
        interval = config.get('schedules', {}).get(bot, {}).get('interval_seconds',
                     {'news': 900, 'certificates': 86400, 'stack': 21600}[bot])
        state.put(f'{bot}:next_due', time.time() + (min(300, interval) if errors else interval))
        state.db.execute('UPDATE runs SET finished=?,status=?,detail=? WHERE id=?',
                         (stamp(), 'failed' if errors else 'success', json.dumps(errors), record))
        state.db.commit()
        state.close()
        LOG.info('Execution finished bot=%s status=%s errors=%s', bot, 'failed' if errors else 'success', errors)
        return not errors


def serve(config, config_path=None):
    stop = threading.Event()
    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, lambda *_: stop.set())
    with lock(config['state_file'] + '.scheduler.lock'), ThreadPoolExecutor(max_workers=3) as executor:
        pending = {}
        LOG.info('Scheduler started; all times UTC')
        while not stop.is_set():
            if config_path:
                try:
                    config = load_config(config_path)
                except (ValueError, OSError, KeyError):
                    LOG.error("Configuration reload failed; keeping last valid configuration")
            state = State(config['state_file'])
            for bot in BOTS:
                if not config.get('schedules', {}).get(bot, {}).get('enabled', True):
                    continue
                future = pending.get(bot)
                if future and not future.done():
                    continue
                if future:
                    try:
                        future.result()
                    except Exception as error:
                        LOG.error('Worker failed bot=%s error=%s', bot, type(error).__name__)
                    del pending[bot]
                if state.get(f'{bot}:next_due', 0) <= time.time():
                    pending[bot] = executor.submit(run, bot, config)
            state.close()
            stop.wait(5)
        LOG.info('Stopping scheduler; waiting for active scans to finish')


def main():
    parser = argparse.ArgumentParser(description='JyotiCVE standalone security monitoring')
    parser.add_argument('--config', default='config.json')
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('validate', help='Validate local configuration without external requests')
    once = sub.add_parser('run', help='Run one or all bots once')
    once.add_argument('bot', choices=[*BOTS, 'all'])
    once.add_argument('--dry-run', action='store_true', help='Preview new events without sending or persisting history')
    sub.add_parser('serve', help='Run all enabled bots on independent persistent schedules')
    web = sub.add_parser('web', help='Open the local browser dashboard')
    web.add_argument('--port', type=int, default=8080)
    sub.add_parser('status', help='Show recent executions and pending notification count')
    args = parser.parse_args()
    formatter = logging.Formatter('%(asctime)sZ %(levelname)s %(message)s', '%Y-%m-%dT%H:%M:%S')
    formatter.converter = time.gmtime
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    logging.basicConfig(level=logging.INFO, handlers=[handler])
    try:
        config = load_config(args.config)
        if args.command == 'validate':
            hosts, tech = domains(config['domains_file']), inventory(config['inventory_file'])
            print(f'Configuration valid: {len(hosts)} domains, {len(tech)} technologies.')
            if not hosts or not tech:
                print('Empty inventories disable corresponding asset coverage; add your actual assets.')
            if all(c['type'] == 'console' for c in config['notifications']):
                print('Console-only delivery: configure a webhook, Slack, or Teams destination for team notifications.')
        elif args.command == 'web':
            from .web import serve_web
            serve_web(args.config, args.port)
        elif args.command == 'serve':
            serve(config, args.config)
        elif args.command == 'status':
            state = State(config['state_file'])
            print(json.dumps({'runs': state.db.execute('SELECT bot,started,finished,status,detail FROM runs ORDER BY id DESC LIMIT 20').fetchall(),
                              'pending_deliveries': state.db.execute('SELECT count(*) FROM deliveries WHERE delivered IS NULL').fetchone()[0]}, indent=2))
            state.close()
        else:
            results = [run(bot, config, args.dry_run) for bot in (BOTS if args.bot == 'all' else [args.bot])]
            return 0 if all(results) else 1
    except (ValueError, OSError, KeyError, RuntimeError) as error:
        LOG.error('%s', error)
        return 2
    return 0
