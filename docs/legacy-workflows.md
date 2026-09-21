# Three cybersecurity Telegram bots

| Bot | Script | Schedule (UTC) | What it alerts on |
| --- | --- | --- | --- |
| 1: News and CVEs | `.github/scripts/sec_bot.py` | Every 15 minutes | Both The Hacker News and Hacker News (Y Combinator), newly published NVD CVEs, and recent CISA KEV additions |
| 2: Certificates | `.github/scripts/cert_expiry_bot.py` | Daily at 02:00 | Expired certificates, expiry within 30 days, invalid certificates, and failed TLS checks for hosts in `domains.txt` |
| 3: Your technology stack | `.github/scripts/tech_stack_cve_bot.py` | Every 6 hours | OSV advisories affecting the package versions in `tech_stack.json`, enriched with CISA KEV and EPSS |

Each bot has its own manually runnable GitHub Actions workflow. Schedules run from the default branch and may be delayed by GitHub. The supplied domain and package inventories are empty: configure them to activate Bots 2 and 3. Empty inventories are explicitly reported in workflow logs.

## Telegram configuration

In repository **Settings → Secrets and variables → Actions**, set `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID` as shared defaults. Set `NVD_API_KEY` for Bot 1's optional higher NVD request limit.

For three separate Telegram bot identities/destinations, create the bots with BotFather and configure these optional overrides:

| Bot | Token secret | Chat secret |
| --- | --- | --- |
| News/CVEs | `NEWS_TELEGRAM_BOT_TOKEN` | `NEWS_TELEGRAM_CHAT_ID` |
| Certificates | `CERT_TELEGRAM_BOT_TOKEN` | `CERT_TELEGRAM_CHAT_ID` |
| Technology stack | `TECH_STACK_TELEGRAM_BOT_TOKEN` | `TECH_STACK_TELEGRAM_CHAT_ID` |

Each missing override falls back to its shared secret. The bots must have access to their destination chats. For local execution, export `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID` for the bot you are running; the per-bot overrides are mapped by the workflows.

## Bot 1: News and general CVEs

Pulls a rolling six-hour window, including unscored NVD records. Alerts contain full descriptions, CVSS v4/v3/v2 data when available, dates, status, and reference links. Missing EPSS scores are labeled unavailable. Absence from KEV does not mean a vulnerability is safe. Older CVEs newly added to KEV are checked separately.

The Hacker News alerts include the summary supplied in its RSS feed and a source link. Y Combinator search supplies titles and links, not full articles.

```sh
python .github/scripts/sec_bot.py --hours 6 --news-source both
```

Use `--high-risk-only` to restrict NVD alerts to KEV, EPSS >10%, or CVSS >=9. `--news-source` accepts `hn`, `thn`, `both`, or `none`. Optional `--domain example.com` prints passive subdomain results; it is unrelated to Bot 2's TLS monitoring.

The lookback is not a historical backfill: outages longer than six hours can miss records. Increase `--hours` when recovering (maximum 120 days). NVD monitoring uses publication time, not later modifications of old CVEs. CISA's additions have date-only precision, so the entire cutoff day is included. Feeds and search services may limit retained results.

## Bot 2: Certificate validation

Edit `domains.txt`, one host per line:

```text
example.com
app.example.com:8443
```

Blank lines and `#` comments are accepted. Do not include URL schemes or paths. The default port is 443; the bot uses TLS SNI and validates the hostname and trust chain. If validation fails, a second diagnostic connection reads the certificate's dates while retaining the validation failure in the alert. This is not a revocation/OCSP monitor.

```sh
python .github/scripts/cert_expiry_bot.py --warn-days 30
python .github/scripts/cert_expiry_bot.py --dry-run
```

Healthy certificates are logged without sending Telegram messages. Problems generate a reminder on each daily run. `CHECK FAILED` means the certificate could not be checked, not that it is expired, and causes a failed workflow after other hosts have been checked. An expired certificate successfully reported to Telegram is a completed check.

## Bot 3: Vulnerabilities affecting your software

Edit `tech_stack.json` with your actual installed packages and exact versions:

```json
[
  {"name": "django", "ecosystem": "PyPI", "version": "4.2.16"},
  {"name": "express", "ecosystem": "npm", "version": "4.21.0"},
  {"name": "org.apache.logging.log4j:log4j-core", "ecosystem": "Maven", "version": "2.14.1"}
]
```

These are illustrative versions, **not upgrade recommendations or your confirmed inventory**. A copy is in `tech_stack.example.json`. Use OSV's exact package and ecosystem names, including case and distribution/release qualification when applicable (for example, a Debian release-specific ecosystem). Versions must be JSON strings. Inventory names are not inferred from web scanners.

```sh
python .github/scripts/tech_stack_cve_bot.py
python .github/scripts/tech_stack_cve_bot.py --dry-run
```

Every run queries all configured versions, so newly indexed advisories are found without relying on a publication-date window. The first run also reports existing vulnerabilities. CVE aliases are used for KEV/EPSS lookups; advisories without a CVE are clearly labeled and still reported. Withdrawn records are excluded. Fixed versions are shown for the matching package when supplied; review the advisory for the appropriate supported release branch.

The bot only covers the packages and versions you list and the records available in OSV. It does not discover installed software, expand transitive dependencies, or guarantee coverage of proprietary appliances. Update the inventory after upgrades. Invalid OSV queries and source failures are reported rather than treated as a clean scan.

## Delivery history and failure handling

Long alerts are split into Telegram messages without truncating text. Plain text preserves punctuation and links. Failed deliveries are not marked successful; failures cause visible workflow errors, with source warnings sent where possible. `--dry-run` performs read-only checks and sends no Telegram messages or updates to delivery history.

Bot 1 stores content fingerprints in `.bot-state/sent.json` for seven days; changed content can be sent again. Bot 3 stores advisory/CVE identities per package and version in `.tech-stack-state/tech_stack_cve_state.json` without time-based expiry. Repeated findings and alias-equivalent advisories are skipped, even when advisory text or EPSS changes. A different installed version has separate history.

Both histories are persisted using separate GitHub Actions caches, including after partial failures. **No workflow commits state to the repository; all three use `contents: read`.** Cache deletion/eviction can reset history and produce repeat alerts. Retrying a partially sent multipart message can also repeat delivered parts. Cache history is not a durable exactly-once guarantee. Local history persists on disk; `--state-file` selects an alternate location for either CVE bot.

## Install and test

```sh
python -m pip install -r .github/scripts/requirements.txt
python -m unittest discover -s tests -v
```

Tests use mocked external services and locally generated certificates; they send no Telegram messages. After configuring inventories and secrets, run each bot from the Actions tab to verify your deployment.

API references: [Telegram](https://core.telegram.org/bots/api#sendmessage), [NVD](https://nvd.nist.gov/developers/vulnerabilities), [OSV package/version queries](https://google.github.io/osv.dev/post-v1-query/), [GitHub cache behavior](https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching).
