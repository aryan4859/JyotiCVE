"""
Bot 2: TLS Certificate Expiry Monitor

Connects to each domain in a given list over TLS, reads the server
certificate's expiry date, and sends a Telegram alert for anything already
expired or expiring within a configurable warning window. Meant to run once
a day.
"""
import ssl
import socket
import argparse
from datetime import datetime, timezone

from alert_utils import send_telegram_alert

DEFAULT_WARN_DAYS = 30
DEFAULT_PORT = 443
DEFAULT_TIMEOUT = 10


def load_domains(path):
    domains = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    domains.append(line)
    except OSError as e:
        print(f"Could not read domain list '{path}': {e}")
    return domains


def get_cert_expiry(domain, port=DEFAULT_PORT, timeout=DEFAULT_TIMEOUT):
    """Returns (expiry_datetime, error_message). Exactly one will be None."""
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
        not_after = cert.get("notAfter")
        if not not_after:
            return None, "Certificate has no notAfter field"
        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        return expiry, None

    except ssl.SSLCertVerificationError as e:
        return None, f"Certificate verification failed: {e}"
    except (socket.timeout, TimeoutError):
        return None, f"Connection to {domain}:{port} timed out"
    except (socket.gaierror, ConnectionRefusedError, OSError) as e:
        return None, f"Could not connect to {domain}:{port}: {e}"
    except Exception as e:
        return None, f"Unexpected error checking {domain}: {e}"


def check_domains(domains, warn_days=DEFAULT_WARN_DAYS, port=DEFAULT_PORT, timeout=DEFAULT_TIMEOUT):
    now = datetime.now(timezone.utc)
    alert_count = 0

    for domain in domains:
        expiry, error = get_cert_expiry(domain, port=port, timeout=timeout)

        if error:
            print(f" - {domain}: ERROR - {error}")
            send_telegram_alert(
                domain,
                {"Status": "⚠️ Could not verify certificate", "Detail": error},
                header="🔒 *[CERTIFICATE CHECK FAILED]*"
            )
            alert_count += 1
            continue

        days_left = (expiry - now).days
        print(f" - {domain}: expires {expiry.date()} ({days_left} day(s) left)")

        if days_left < 0:
            send_telegram_alert(
                domain,
                {
                    "Status": "🔴 EXPIRED",
                    "Expired On": str(expiry.date()),
                    "Days Overdue": str(abs(days_left)),
                },
                header="🔒 *[CERTIFICATE EXPIRED]*"
            )
            alert_count += 1
        elif days_left <= warn_days:
            send_telegram_alert(
                domain,
                {
                    "Status": "🟡 Expiring Soon",
                    "Expires On": str(expiry.date()),
                    "Days Remaining": str(days_left),
                },
                header="🔒 *[CERTIFICATE EXPIRING SOON]*"
            )
            alert_count += 1

    print(f"Checked {len(domains)} domain(s), sent {alert_count} alert(s).")


def main():
    parser = argparse.ArgumentParser(
        description="Check TLS certificate expiry for a list of domains and alert via Telegram."
    )
    parser.add_argument(
        "--domains-file", default="domains.txt",
        help="Path to a text file with one domain per line (default: domains.txt)"
    )
    parser.add_argument(
        "--domains", default=None,
        help="Comma-separated list of domains, used instead of --domains-file"
    )
    parser.add_argument(
        "--warn-days", type=int, default=DEFAULT_WARN_DAYS,
        help=f"Alert if a certificate expires within this many days (default: {DEFAULT_WARN_DAYS})"
    )
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="TLS port (default: 443)")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Connection timeout in seconds")
    args = parser.parse_args()

    if args.domains:
        domains = [d.strip() for d in args.domains.split(",") if d.strip()]
    else:
        domains = load_domains(args.domains_file)

    if not domains:
        print("No domains to check. Provide --domains or a --domains-file with at least one entry.")
        return

    print(f"Checking certificate expiry for {len(domains)} domain(s)...")
    check_domains(domains, warn_days=args.warn_days, port=args.port, timeout=args.timeout)


if __name__ == "__main__":
    main()
