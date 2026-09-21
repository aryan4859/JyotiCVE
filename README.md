# Cybersecurity news and CVE Telegram bot

Every 15 minutes, the GitHub Actions workflow checks a rolling six-hour window for:

- Newly published NVD CVEs, including unscored records, with complete descriptions, CVSS v4/v3/v2 information, dates, status, and reference links.
- CISA Known Exploited Vulnerabilities additions, including older CVEs newly added to KEV, with required actions and due dates.
- Security stories on both The Hacker News and Hacker News (Y Combinator).

EPSS enriches CVE alerts when available. Missing scores are labeled unavailable; absence from KEV does not mean a vulnerability is safe. News contains the summary supplied by the feed and a source link; Y Combinator search supplies titles and links, not full articles.

## Setup

In GitHub repository **Settings → Secrets and variables → Actions**, configure:

| Secret | Purpose |
| --- | --- |
| `TELEGRAM_BOT_TOKEN` | Required Telegram bot token |
| `TELEGRAM_CHAT_ID` | Required destination chat ID; the bot must have access |
| `NVD_API_KEY` | Optional NVD API key for a higher request limit; the workflow passes it to the bot |

Push these files to the default branch and run **Actions → Cybersecurity Intel & CVE Alert Bot → Run workflow** to check delivery. The schedule then runs automatically, subject to GitHub scheduling delays.

## Local execution

Export the same credentials in your environment, then run:

```sh
python -m pip install -r .github/scripts/requirements.txt
python .github/scripts/sec_bot.py --hours 6 --news-source both
```

All newly published CVEs are included by default. Add `--high-risk-only` for the previous threshold behavior (KEV, EPSS >10%, or CVSS >=9). Choose `--news-source hn`, `thn`, `both`, or `none`. Optional `--domain example.com` prints passive subdomain results locally; this lookup is not needed for news delivery.

## Delivery and limitations

Long alerts are split across Telegram messages without truncating their text. Plain-text messages preserve punctuation in descriptions and links. Successful alerts are recorded in `.bot-state/sent.json`; GitHub Actions restores/saves this directory using its cache, including after a partially failed run. Identical alert content is skipped for seven days; changed details can produce an updated alert. Failed deliveries are not recorded as successful.

The six-hour overlap tolerates ordinary schedule delays. It is not a historical backfill: outages longer than the lookback can miss records. Increase `--hours` when recovering (maximum 120 days). NVD monitoring is based on publication time, so later modifications to older CVEs are not scanned. CISA only supplies a date for additions, so its window includes the entire cutoff day. Feeds/search services may limit retained results. Cache eviction or retrying a partially delivered multipart alert can cause duplicates; delivery is not exactly once.

Source failures generate a Telegram warning where possible and fail the workflow visibly. Delivery failures also fail the workflow. Logs omit Telegram exception URLs to protect the bot token. Missing required Telegram credentials stop execution immediately.

## Tests

```sh
python -m unittest discover -s tests -v
```

Tests mock external services; they send no Telegram messages. They cover pagination, complete descriptions, CVSS v4, message splitting, API rejection, rate limiting, missing scores, news without matching CVEs, older KEV additions, feed parsing, and successful-delivery persistence.

API references: [Telegram sendMessage](https://core.telegram.org/bots/api#sendmessage), [NVD CVE API](https://nvd.nist.gov/developers/vulnerabilities), [Hacker News search API](https://hn.algolia.com/api).
