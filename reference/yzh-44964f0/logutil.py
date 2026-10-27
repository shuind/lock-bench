"""Beijing timestamps for operational stderr logs; stdout remains machine-readable."""

from datetime import datetime, timedelta, timezone
import sys
import time

BEIJING = timezone(timedelta(hours=8))


def log_line(message, *, wall_time_ns=None):
    ns = time.time_ns() if wall_time_ns is None else wall_time_ns
    stamp = (
        datetime.fromtimestamp(ns // 10**9, BEIJING)
        .replace(microsecond=(ns % 10**9) // 1000)
        .strftime('%Y-%m-%d %H:%M:%S.%f')
    )[:-3]
    lines = str(message).splitlines() or ['']
    sys.stderr.write(''.join(f'{stamp} {line}\n' for line in lines))
    sys.stderr.flush()
