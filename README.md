# JyotiCVE — standalone security monitoring

Three independent scheduled Python bots share durable SQLite history and a retryable notification queue. Run the tool on a Linux host or VM; GitHub Actions is **not** the scheduler. Existing Actions workflows are retained for manual legacy use, with their automatic schedules disabled.

| Bot | Default schedule | Work |
| --- | --- | --- |
| `news` | Every 15 minutes | Hacker News security stories, new/modified NVD CVEs, new/changed CISA KEV entries |
| `certificates` | Every 24 hours | HTTPS certificate validation, threshold alerts, recovery alerts, daily UTC summary |
| `stack` | Every 6 hours | NVD/CISA intelligence matched to the organization's explicit product/version inventory |

For cloud hosting, use the included **[Render deployment guide](docs/hosting.md)** and `render.yaml`. It configures an authenticated dashboard, automatic monitoring, and persistent storage on a paid service. The local `web` command remains loopback-only.

See [`.env.example`](.env.example) for required hosting settings and optional API key/webhook placeholders. For local use, copy it to `.env`, fill in the values, then run `set -a; source .env; set +a` before starting the app. The app does not automatically load `.env`; on Render, configure the values in the service's Environment settings. PostgreSQL is not yet supported.

## Browser dashboard

Start the local web UI with your existing environment:

```sh
cd ~/Documents/JyotiCVE
source .venv/bin/activate
python -m jyoticve web
```

Open **http://127.0.0.1:8080**. Choose another port with `python -m jyoticve web --port 8090`.

The dashboard provides:

- Overview of monitored assets, recorded critical events, pending deliveries, and workflow status.
- Search and filter the latest 200 alerts, inspect full finding details, and open investigation links.
- Edit domain lists and add, edit, or remove technologies with explicit product/version identifiers.
- Configure schedules, certificate thresholds, news keywords, and notification channel metadata. Secret URLs stay in server environment variables.
- Run **Preview scan** without notifications or saved history, or **Run now** for a normal scan. Preview output is available in **Run history** for this dashboard session.
- Start and pause its own scheduler. An existing terminal/service scheduler is detected and shown as externally managed; control that process in its original terminal or service.

The dashboard does not start scheduled monitoring automatically. Click **Start monitoring** when ready. Keep the dashboard terminal open. Ctrl+C stops the web server and asks its scheduler to stop after active scans finish; manually requested scans may finish in the background. New scheduler processes reload configuration each tick; restart a scheduler launched before this dashboard update to enable configuration reloading.

The server binds only to the loopback interface. It is a local single-user workspace, with Host/Origin checks and an anti-CSRF token for edits, not a public authenticated service. No Node.js install or frontend build is needed. Assets are included in the Python package. Configuration and inventory writes are validated before atomic replacement.

## Quick start

Requires Linux, Python 3.11+, outbound HTTPS and DNS access, and persistent local storage.

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
cp config.example.json config.json
python -m jyoticve validate
python -m jyoticve run certificates --dry-run
python -m jyoticve serve
```

The installed `jyoticve` command is equivalent to `python -m jyoticve`. `serve` remains in the foreground; use the systemd unit below to run continuously across logout and reboot. Enabled bots are immediately due on first startup, then run at configurable intervals from completion. Due times persist across restarts. Overdue jobs run once on startup, and NVD catches up from the last successful cursor. A daily certificate interval is 24 hours from completion, not a fixed wall-clock time.

The supplied domain and technology inventories are empty and delivery defaults to console. Populate them and configure a team destination to activate real monitoring. Examples are illustrative, not an assertion about your organization or suggested software versions.

```sh
python -m jyoticve --config /path/to/config.json validate
python -m jyoticve run news --dry-run
python -m jyoticve run stack
python -m jyoticve run all
python -m jyoticve status
```

`--config` precedes the subcommand. Dry runs fetch external sources but copy any existing history into memory, send only new preview events to stdout, and do not persist history or delivery changes. They may create an empty lock file. A dry run against existing history suppresses already-seen items. Tests are fully offline.

## Configuration

Paths in JSON are relative to the configuration file. `config.example.json` documents schedules, lookback, timeouts, TLS thresholds, and news filters. Keep credentials in environment variables, not committed JSON.

Set `NVD_API_KEY` optionally. Requests are paced across both intelligence threads at approximately one per 6.1 seconds without a key or 0.7 seconds with one. Separate processes/hosts sharing an API key must coordinate their own aggregate rate. Do not run multiple scheduler installations against one database; a local SQLite database is not a distributed queue.

### Team notifications

Replace `notifications` in `config.json`, for example:

```json
"notifications": [
  {"id": "security-slack", "type": "slack", "url_env": "SECURITY_SLACK_WEBHOOK"},
  {"id": "security-siem", "type": "webhook", "url_env": "SECURITY_WEBHOOK"}
]
```

```sh
export SECURITY_SLACK_WEBHOOK='https://your-slack-incoming-webhook'
export SECURITY_WEBHOOK='https://your-https-receiver'
export NVD_API_KEY='your-optional-nvd-api-key'
```

Supported channels are `console`, `webhook`, `slack` incoming webhooks, and `teams` Adaptive Card webhook/workflow receivers. A Teams workflow must accept the documented Adaptive Card envelope; configure its HTTP trigger accordingly. A generic webhook receives the structured event with `event_id`, `title`, `severity`, `kind`, `summary`, and `details`. An email gateway can consume this webhook; direct SMTP is not implemented.

All configured channels receive events. Channel IDs must stay stable: queued deliveries reference them. Changing a destination URL retains history; adding a channel applies to future events, without replaying historical events. Failed deliveries are retried, and already delivered channels/message chunks are not intentionally resent. Slack and Teams messages are split to keep individual payloads manageable. Keep webhook URLs secret; request errors do not log them.

### Domains and certificate thresholds

Edit `domains.txt`:

```text
# Hostnames only, optional port; no scheme or path
example.com
app.example.com:8443
```

The bot uses SNI and the system trust store to validate hostname, validity dates, and certificate chain. A failed validation permits a second **diagnostic-only** connection to extract the certificate; this never turns a failed check into a valid result. Details include UTC validity dates, days remaining, issuer, subject, DNS SANs, leaf fingerprint, validation errors, and connection errors.

Default thresholds are 30, 14, 7, and 3 days. A threshold is crossed when remaining time is at or below that boundary. Expired/invalid certificates and TLS failures are critical; expiration within `certificate_critical_days` (default 7) is high; other approaching expirations are medium. The same issue is suppressed until the certificate, status, severity, or threshold changes. Recovery is reported. Each UTC day receives one informational summary containing every domain, including failures and an explicit empty-inventory flag. Revocation/OCSP, cipher auditing, and full trust-chain export are not implemented.

### Technology inventory

Edit `inventory.json`; use `inventory.example.json` as a schema example. Every entry needs a unique `id`, display `name`, exact deployed `version`, and either a complete CPE 2.3 string or explicit NVD `vendor`/`product` identifiers. `part` is `a` (application, default), `o` (operating system), or `h` (hardware).

```json
[
  {
    "id": "production-framework",
    "name": "Django",
    "category": "framework",
    "vendor": "djangoproject",
    "product": "django",
    "version": "4.2.16",
    "version_scheme": "pep440",
    "package": {"ecosystem": "PyPI", "name": "django"}
  }
]
```

Use categories for OSes, languages, frameworks, packages, databases, web/application servers, containers, cloud products, network/security products, and other software. Explicit `aliases` can contain additional `["vendor", "product"]` pairs. Package coordinates are recorded in alerts, but **must be mapped to an NVD product/CPE**; this tool does not guess a product from a package name, discover software, expand dependencies, or query a cloud provider's tenant configuration. The retained legacy OSV script can cover ecosystem-native package advisories separately.

Matching evaluates vulnerable CPE criteria, exact versions, inclusive/exclusive range bounds, platform qualifiers, and AND/OR environmental constraints. Numeric dotted versions use numeric release ordering. Set `version_scheme: "pep440"` only for a technology known to follow that scheme. Unknown/vendor-specific ordering, missing platform qualifiers, or unverified environmental requirements produce an informational `review` event, never a confirmed stack alert. Products/versions clearly outside the affected criteria produce no stack alert. Unknown applicability is not proof of safety. CPE data may be incomplete or delayed, and a product/version match still requires checking actual deployment prerequisites in the vendor advisory.

The first stack run and each inventory change backfill all NVD records for listed products, so an older CVE affecting a newly added asset is found. Subsequent runs use modified-date cursors and independently check KEV changes. Backfills for broad products can take substantial time and API requests.

## Workflow and priority model

Each workflow follows **collection → normalization → filtering → analysis/matching → deduplication → severity classification → alert generation → notification → logging/state update**. Queue insertion and the event fingerprint are atomic; source cursors advance only after that source's complete scan has been queued. Delivery success is tracked separately, so an unavailable destination does not lose collected events.

- **Critical:** known exploitation (KEV), confirmed critical stack CVE, expired/invalid certificate or TLS connection failure.
- **High:** high/critical general CVE intelligence, high confirmed stack CVE, critical certificate expiry window, or incomplete monitoring.
- **Medium:** other confirmed stack CVEs, approaching certificate expiry, or significant security news headlines.
- **Informational:** general news/lower-severity CVEs without identified impact, uncertain stack applicability needing review, recoveries, and daily summaries.

CVE alerts include CVE ID, available CVSS/severity, products/CPEs and affected criteria, description, published/updated dates, exploitation/KEV status, remediation guidance, and references. Stack alerts also include matched inventory entries, deployed versions, and match confidence. CISA remediation instructions are used when supplied; otherwise the tool points to vendor advisories rather than inventing a fixed release. Absence from KEV means exploitation is unknown, not disproven.

Hacker News here means **Y Combinator's Hacker News via Algolia**. Configurable keyword searches identify relevant stories; significant headline terms distinguish actionable review from general information. News summaries are concise headline summaries, not article-body analysis or independently verified claims. HN has no reliable update cursor: newly indexed/published stories and changes inside the overlap window are covered, but edits to older stories are not guaranteed. Saturated search windows fail visibly rather than silently discarding excess results.

## Reliability and state

- SQLite stores UTC run history, source cursors, normalized CVE cache, meaningful event fingerprints, events, and per-channel delivery progress. Keep the database and its WAL on persistent storage; back it up using SQLite's backup API.
- NVD uses `lastModStartDate`/`lastModEndDate` with a five-minute overlap, pagination, and sub-120-day windows for long outages. Timestamp-only edits do not repeat an alert; descriptions, severity, affected versions, references, inventory applicability and KEV/remediation changes can.
- Initial general intelligence covers the configured lookback (24 hours by default). Historical KEV entries form a baseline; new/changed KEV entries are independently enriched even when the original CVE is old. Stack inventory backfill includes historical product CVEs.
- A failed source retains its cursor. Partial results already queued deduplicate on retry. KEV failure defers CVE scans rather than falsely reporting no exploitation; HN continues independently. Malformed records fail the affected scan visibly, preserving the cursor for investigation.
- HTTP requests use finite timeouts and bounded retries, including `Retry-After` handling. Missing/unavailable domains do not stop other certificate checks. Worker threads isolate the three schedules. Failed runs retry within five minutes or the configured interval, whichever is shorter.
- Execution start/result logs use UTC and are written to stderr; systemd captures them in the journal. Incomplete collection produces a distinct operational event and a nonzero one-shot exit status. Per-bot advisory file locks prevent overlapping local runs.
- Delivery is **at least once**, not exactly once: a crash or ambiguous network response after a receiver accepted a message can duplicate it. Generic receivers can deduplicate the `Idempotency-Key` header. Removing state resets history. History is retained indefinitely; monitor disk usage and apply an organization-specific archival policy.
- Inventory is read on each execution; the scheduler reloads configuration between ticks; restart it after changing environment variables. SQLite exposes local history through `status` and the local browser dashboard. There is no public authentication server.

## Run unattended with systemd

A service template is in [`deploy/jyoticve.service`](deploy/jyoticve.service). Install the project and virtual environment under `/opt/jyoticve`, create a dedicated `jyoticve` system user, and give it read access to configuration and inventories. Set `state_file` in `/opt/jyoticve/config.json` to `/var/lib/jyoticve/monitor.sqlite3`. The service creates that state directory and grants write access there.

Put required environment variables in `/etc/jyoticve.env` (root-owned, mode `0600`, one `NAME=value` per line). After adapting paths and configuring a real destination:

```sh
sudo cp deploy/jyoticve.service /etc/systemd/system/jyoticve.service
sudo systemctl daemon-reload
sudo systemctl enable --now jyoticve
sudo systemctl status jyoticve
sudo journalctl -u jyoticve -f
```

The service template is provided, not installed or started automatically by this repository. No destination credentials or organization inventories are bundled.

## Tests and extension points

```sh
python -m pip install -e '.[hosted]'
python -m unittest discover -s tests -v
```

Tests mock external sources and delivery, and generate local certificate fixtures. Modules separate `sources.py`, `matching.py`, `certificates.py`, `bots.py`, shared `core.py`, and the CLI/scheduler. Add source adapters without changing the queue; add channels in the delivery adapter. Legacy scripts and their tests remain under `.github/scripts`; [legacy documentation](docs/legacy-workflows.md) describes their different behavior and limitations.

Source API references: [NVD CVE API](https://nvd.nist.gov/developers/vulnerabilities), [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), [Hacker News Algolia API](https://hn.algolia.com/api).
