"""Single-instance runtime: SQLite, local locks, and scheduler ownership are shared."""
import os

bind = '0.0.0.0:' + os.environ.get('PORT', '10000')
workers = 1
worker_class = 'gthread'
threads = 8
preload_app = False
# Workers must not recycle during scans; the process supervisor restarts on failure.
max_requests = 0
timeout = 60
graceful_timeout = 50
umask = 0o077
accesslog = '-'
errorlog = '-'
# Avoid logging credentials, query strings, or request headers.
access_log_format = '%(t)s %(m)s %(U)s %(s)s %(L)s'


def worker_exit(server, worker):
    dashboard = getattr(worker.wsgi, 'dashboard', None)
    if dashboard is not None:
        dashboard.close()
