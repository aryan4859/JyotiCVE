"""Daily TLS certificate validation for an explicit list of hosts."""
import argparse
import math
import socket
import ssl
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from cryptography import x509
import sec_bot as common


def load_domains(path):
    domains = []
    for number, line in enumerate(Path(path).read_text().splitlines(), 1):
        value = line.split('#', 1)[0].strip()
        if not value:
            continue
        try:
            parsed = urlsplit('//' + value)
            if (not parsed.hostname or parsed.username or parsed.password or
                    parsed.path or parsed.query or parsed.fragment):
                raise ValueError()
            host = parsed.hostname.encode('idna').decode('ascii')
            port = 443 if parsed.port is None else parsed.port
            if any(c.isspace() for c in host) or not 1 <= port <= 65535:
                raise ValueError()
        except (ValueError, UnicodeError):
            raise ValueError(f'{path}:{number}: use a hostname or hostname:port, without a URL/path') from None
        if (host, port) not in domains:
            domains.append((host, port))
    return domains


def read_certificate(host, port, context, timeout):
    with socket.create_connection((host, port), timeout=timeout) as connection:
        with context.wrap_socket(connection, server_hostname=host) as tls:
            return x509.load_der_x509_certificate(tls.getpeercert(binary_form=True))


def check_certificate(host, port=443, warn_days=30, timeout=10, now=None):
    now = now or datetime.now(timezone.utc)
    verification_error = None
    try:
        try:
            certificate = read_certificate(host, port, ssl.create_default_context(), timeout)
        except ssl.SSLCertVerificationError as error:
            verification_error = error.verify_message or str(error)
            # Inspect dates even for an expired/untrusted certificate. This second
            # connection is diagnostic only; it never changes the failed validation.
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            certificate = read_certificate(host, port, context, timeout)
        expiry = certificate.not_valid_after_utc
        starts = certificate.not_valid_before_utc
        remaining = (expiry - now).total_seconds()
        if remaining <= 0:
            status = 'EXPIRED'
        elif starts > now:
            status = 'NOT YET VALID'
        elif verification_error:
            status = 'INVALID TLS CERTIFICATE'
        elif remaining <= warn_days * 86400:
            status = 'EXPIRING SOON'
        else:
            status = 'VALID'
        return {'Domain': f'{host}:{port}', 'Status': status,
                'Expires (UTC)': expiry.isoformat(),
                'Days remaining': math.floor(remaining / 86400),
                'Issuer': certificate.issuer.rfc4514_string(),
                'TLS validation': verification_error or 'Passed hostname and trust-chain validation'}
    except (OSError, ValueError) as error:
        return {'Domain': f'{host}:{port}', 'Status': 'CHECK FAILED',
                'Error': str(error), 'TLS validation': verification_error or 'Could not complete validation'}


def run(domains, warn_days=30, timeout=10, dry_run=False):
    failed = False
    for host, port in domains:
        details = check_certificate(host, port, warn_days, timeout)
        print(details)
        if details['Status'] == 'CHECK FAILED':
            failed = True
        if details['Status'] != 'VALID' and not dry_run:
            if not common.send_telegram_alert('Certificate alert', details):
                failed = True
    if failed:
        raise RuntimeError('Certificate check or alert delivery failed; see output above')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--domains-file', default='domains.txt')
    parser.add_argument('--warn-days', type=int, default=30)
    parser.add_argument('--timeout', type=float, default=10)
    parser.add_argument('--dry-run', action='store_true', help='Check TLS and print results without sending Telegram')
    args = parser.parse_args()
    if args.warn_days < 0 or args.timeout <= 0:
        parser.error('--warn-days must be nonnegative and --timeout must be positive')
    domains = load_domains(args.domains_file)
    if not domains:
        print('No domains configured. Add your hosts to domains.txt to enable monitoring.')
        return
    if not args.dry_run and not (common.TELEGRAM_BOT_TOKEN and common.TELEGRAM_CHAT_ID):
        parser.error('Set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID')
    run(domains, args.warn_days, args.timeout, args.dry_run)


if __name__ == '__main__':
    main()
