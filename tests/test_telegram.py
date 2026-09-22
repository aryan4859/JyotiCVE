import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from jyoticve.core import State, deliver, load_config, render, telegram_chunks
from jyoticve.web import Dashboard


class TelegramTests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(os.environ, TELEGRAM_BOT_TOKEN='123456:sample_token', TELEGRAM_CHAT_ID='-100123456')
        self.env.start()
        self.addCleanup(self.env.stop)
        self.channel = {'id': 'telegram', 'type': 'telegram', 'token_env': 'TELEGRAM_BOT_TOKEN', 'chat_id_env': 'TELEGRAM_CHAT_ID'}
        self.state = State(':memory:')
        self.addCleanup(self.state.close)
        self.config = {'notifications': [self.channel]}

    def test_unicode_chunks_preserve_message(self):
        message = 'a😀\n' * 5000
        chunks = list(telegram_chunks(message))
        self.assertEqual(''.join(chunks), message)
        self.assertTrue(all(len(c.encode('utf-16-le')) // 2 <= 4096 for c in chunks))

    def test_plain_text_delivery_and_resume(self):
        payload = {'title': '<test>_[plain]', 'summary': '😀' * 5000}
        self.state.event('news', 'one', payload, [self.channel])
        ok = Mock(); ok.json.return_value = {'ok': True}
        http = Mock(); http.request.side_effect = [ok, RuntimeError('failed')]
        self.assertEqual(deliver(self.state, self.config, http), 1)
        self.assertEqual(self.state.db.execute('SELECT parts_sent FROM deliveries').fetchone()[0], 1)
        first = http.request.call_args_list[0].kwargs['json']
        self.assertEqual(first['chat_id'], '-100123456')
        self.assertNotIn('parse_mode', first)
        http.reset_mock(); http.request.side_effect = None; http.request.return_value = ok
        self.assertEqual(deliver(self.state, self.config, http), 0)
        self.assertEqual(http.request.call_args_list[0].kwargs['json']['text'], list(telegram_chunks(render(payload)))[1])
        http.reset_mock()
        self.assertEqual(deliver(self.state, self.config, http), 0)
        http.request.assert_not_called()

    def test_api_rejection_and_invalid_json_remain_pending(self):
        self.state.event('news', 'one', {'title': 'test'}, [self.channel])
        http = Mock(); http.request.return_value.json.return_value = {'ok': False}
        self.assertEqual(deliver(self.state, self.config, http), 1)
        http.request.return_value.json.side_effect = ValueError('invalid JSON')
        self.assertEqual(deliver(self.state, self.config, http), 1)
        self.assertEqual(self.state.db.execute('SELECT delivered,parts_sent FROM deliveries').fetchone(), (None, 0))

    def test_settings_roundtrip_and_secret_not_exposed(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            path = root / 'config.json'
            config = json.loads(Path('config.example.json').read_text())
            path.write_text(json.dumps(config))
            (root / 'domains.txt').write_text('')
            (root / 'inventory.json').write_text('[]')
            dashboard = Dashboard(path)
            try:
                dashboard.save('settings', self.config)
                snapshot = dashboard.snapshot()
                self.assertEqual(snapshot['settings']['notifications'], [self.channel])
                self.assertNotIn('sample_token', json.dumps(snapshot))
                with patch.dict(os.environ, TELEGRAM_BOT_TOKEN='https://invalid.example/token'):
                    with self.assertRaises(ValueError):
                        load_config(path)
                with patch.dict(os.environ, TELEGRAM_CHAT_ID=''):
                    with self.assertRaises(ValueError):
                        load_config(path)
            finally:
                dashboard.close()
