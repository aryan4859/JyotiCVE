"""TLS validation and certificate diagnostics with stable issue fingerprints."""
import math
import socket
import ssl
from pathlib import Path
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from .core import now


def domains(path):
    result = []
    for number, line in enumerate(Path(path).read_text().splitlines(), 1):
        value = line.split('#', 1)[0].strip()
        if not value:
            continue
        parsed = urlsplit('//' + value)
        if not parsed.hostname or parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment:
            raise ValueError(f'Invalid domain on line {number}; use hostname[:port]')
        host, port = parsed.hostname.encode('idna').decode(), parsed.port or 443
        if any(c.isspace() for c in host) or not 1 <= port <= 65535 or parsed.port == 0:
            raise ValueError(f'Invalid domain on line {number}')
        if (host, port) not in result:
            result.append((host, port))
    return result


def read(host, port, context, timeout):
    with socket.create_connection((host, port), timeout=timeout) as connection:
        with context.wrap_socket(connection, server_hostname=host) as tls:
            return x509.load_der_x509_certificate(tls.getpeercert(binary_form=True))


def check(host, port, thresholds, critical_days=7, timeout=10, current=None):
    current = current or now()
    result = {'domain': f'{host}:{port}', 'checked_at': current.isoformat(), 'severity': 'informational'}
    verification = None
    try:
        try:
            cert = read(host, port, ssl.create_default_context(), timeout)
        except ssl.SSLCertVerificationError as error:
            verification = error.verify_message or 'Certificate validation failed'
            result['verification_code'] = error.verify_code
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            cert = read(host, port, context, timeout)
        seconds = (cert.not_valid_after_utc - current).total_seconds()
        days = seconds / 86400
        threshold = min((n for n in thresholds if days <= n), default=None)
        try:
            sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            sans = []
        result.update({'expires': cert.not_valid_after_utc.isoformat(),
                       'valid_from': cert.not_valid_before_utc.isoformat(), 'days_remaining': math.floor(days),
                       'issuer': cert.issuer.rfc4514_string(), 'subject': cert.subject.rfc4514_string(),
                       'sans': sans, 'certificate_sha256': cert.fingerprint(hashes.SHA256()).hex(),
                       'validation': verification or 'Passed hostname and trust-chain validation', 'threshold': threshold})
        if seconds <= 0:
            result.update(status='expired', severity='critical')
        elif verification or current < cert.not_valid_before_utc:
            result.update(status='invalid', severity='critical')
        elif threshold is not None:
            result.update(status='expiring', severity='high' if days <= critical_days else 'medium')
        else:
            result['status'] = 'valid'
    except (OSError, ValueError) as error:
        result.update(status='connection failure', severity='critical', error_type=type(error).__name__,
                      error=str(error), validation=verification or 'Unable to validate certificate')
    return result


def issue_key(result):
    # Exclude days remaining and check time: only status, certificate or threshold transitions alert.
    return {k: result.get(k) for k in ('status', 'severity', 'certificate_sha256', 'threshold',
                                      'verification_code', 'error_type')}
