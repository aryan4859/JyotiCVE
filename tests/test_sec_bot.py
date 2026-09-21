import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location('sec_bot', Path(__file__).resolve().parents[1] / '.github/scripts/sec_bot.py')
bot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bot)


class BotTests(unittest.TestCase):
    def setUp(self):
        bot.SOURCE_ERRORS.clear()

    def test_nvd_pagination_full_description_and_v4(self):
        description = 'Full [description] _with_ details. ' * 100
        cve = {'id': 'CVE-2026-1', 'descriptions': [{'lang': 'en', 'value': description}],
               'metrics': {'cvssMetricV40': [{'cvssData': {'baseScore': 9.8, 'version': '4.0'}}]},
               'references': [{'url': 'https://example.org/advisory'}]}
        with patch.object(bot, 'get_json', side_effect=[
            {'vulnerabilities': [{'cve': cve}], 'totalResults': 2},
            {'vulnerabilities': [{'cve': {'id': 'CVE-2026-2'}}], 'totalResults': 2},
        ]) as get, patch.object(bot.time, 'sleep'):
            results = bot.fetch_recent_nvd_cves()
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]['description'], description)
        self.assertEqual(results[0]['cvss'], 9.8)
        self.assertEqual(get.call_count, 2)

    def test_split_preserves_all_text_and_emoji(self):
        message = ('🔒 _[data]_ https://example.org/a(b)\n' * 500)
        chunks = list(bot.split_telegram_message(message))
        self.assertEqual(''.join(chunks), message)
        self.assertTrue(all(len(c.encode('utf-16-le')) // 2 <= 3900 for c in chunks))

    @patch.object(bot.time, 'sleep')
    @patch.object(bot, 'TELEGRAM_CHAT_ID', 'test')
    @patch.object(bot, 'TELEGRAM_BOT_TOKEN', 'test')
    def test_delivery_checks_api_result_and_avoids_markdown(self, sleep):
        with patch.object(bot.SESSION, 'post', return_value=Mock(status_code=200, ok=True, json=lambda: {'ok': False, 'error_code': 400})) as post:
            self.assertFalse(bot.send_telegram_alert('Test', {'Description': '_[unescaped]'}))
            self.assertNotIn('parse_mode', post.call_args.kwargs['json'])

    @patch.object(bot.time, 'sleep')
    @patch.object(bot, 'TELEGRAM_CHAT_ID', 'test')
    @patch.object(bot, 'TELEGRAM_BOT_TOKEN', 'test')
    def test_rate_limit_retry_and_multiple_chunks(self, sleep):
        limited = Mock(status_code=429, json=lambda: {'ok': False, 'parameters': {'retry_after': 2}})
        success = Mock(status_code=200, ok=True, json=lambda: {'ok': True})
        with patch.object(bot.SESSION, 'post', side_effect=[limited, success, success]) as post:
            self.assertTrue(bot.send_telegram_alert('Test', {'Description': 'x' * 6000}))
            self.assertEqual(post.call_count, 3)
            self.assertEqual(post.call_args_list[0].kwargs['json'], post.call_args_list[1].kwargs['json'])

    def test_state_remembers_only_successful_deliveries(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'state.json'
            state = bot.DeliveryState(path)
            with patch.object(bot, 'send_telegram_alert', side_effect=[False, True]) as send:
                self.assertEqual(state.deliver('title', {'a': 'b'}), -1)
                self.assertEqual(state.deliver('title', {'a': 'b'}), 1)
                restored = bot.DeliveryState(path)
                self.assertEqual(restored.deliver('title', {'a': 'b'}), 0)
                self.assertEqual(send.call_count, 2)

    def test_missing_epss_is_not_zero(self):
        with patch.object(bot, 'get_json', return_value={'data': [{'cve': 'CVE-1', 'epss': '0'}]}):
            scores = bot.get_epss_scores_bulk(['CVE-1', 'CVE-2'])
        self.assertEqual(scores['CVE-1'], 0)
        self.assertNotIn('CVE-2', scores)

    def test_news_and_old_kev_run_without_new_cves(self):
        today = bot.datetime.now(bot.timezone.utc).date().isoformat()
        state = Mock()
        state.deliver.return_value = 1
        with patch.object(bot, 'get_cisa_kev', return_value={'CVE-2000-1': {'dateAdded': today}}), \
             patch.object(bot, 'fetch_recent_nvd_cves', return_value=[]), \
             patch.object(bot, 'fetch_hackernews_alerts', return_value=[{'title': 'HN', 'url': 'https://example.org', 'source': 'HN'}]), \
             patch.object(bot, 'fetch_the_hacker_news', return_value=[{'title': 'THN', 'url': 'https://example.com', 'source': 'THN'}]):
            bot.process_new_cves(6, state, news_source='both')
        self.assertEqual(state.deliver.call_count, 3)

    def test_default_delivers_unscored_cve_with_unknown_risk(self):
        state = Mock()
        state.deliver.return_value = 1
        cve = dict(id='CVE-2026-1', cvss=None, severity=None, vector=None, version=None,
                   published='today', modified='today', status='Received', description='Full description', references=[])
        with patch.object(bot, 'get_cisa_kev', return_value=None), \
             patch.object(bot, 'fetch_recent_nvd_cves', return_value=[cve]), \
             patch.object(bot, 'get_epss_scores_bulk', return_value={}):
            bot.process_new_cves(6, state, news_source='none')
        details = state.deliver.call_args.args[1]
        self.assertEqual(details['EPSS'], 'Not yet available')
        self.assertEqual(details['CISA KEV'], 'Source unavailable')

    def test_hn_paginates_and_deduplicates_keywords(self):
        page = {'hits': [{'objectID': '1', 'title': 'Security'}], 'nbPages': 2}
        with patch.object(bot, 'get_json', return_value=page) as get:
            news = bot.fetch_hackernews_alerts(['CVE', 'vulnerability'])
        self.assertEqual(get.call_count, 4)
        self.assertEqual(len(news), 1)

    def test_feed_keeps_full_summary(self):
        date = bot.datetime.now(bot.timezone.utc).strftime('%a, %d %b %Y %H:%M:%S +0000')
        response = Mock(content=f'<rss><channel><item><title>News</title><pubDate>{date}</pubDate><link>https://example.org</link><description>&lt;p&gt;Full &amp;amp; complete&lt;/p&gt;</description></item></channel></rss>'.encode())
        with patch.object(bot.SESSION, 'get', return_value=response):
            news = bot.fetch_the_hacker_news()
        self.assertEqual(news[0]['summary'], 'Full & complete')


if __name__ == '__main__':
    unittest.main()
