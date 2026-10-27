"""Collector lifecycle contract and orchestration; no concrete collector imports."""

from pathlib import Path
import time
from typing import Optional, Protocol


class Collector(Protocol):
    def prepare(self) -> None: ...
    def start(self) -> None: ...
    def cpu_ns(self) -> int: ...
    def stop(self) -> None: ...
    def result(self) -> dict: ...
    def close(self) -> None: ...


class CollectorFactory(Protocol):
    def __call__(self, directory: Path) -> Collector: ...


def run(collectors: dict[str, Collector], duration: Optional[float] = None):
    """Coordinate independent collectors and return their separate results."""
    values = list(collectors.values())
    interrupted = False
    try:
        for collector in values:
            collector.prepare()
        start = time.monotonic_ns()
        for collector in values:
            collector.start()
        deadline = start / 1e9 + duration if duration is not None else None
        try:
            while deadline is None or time.monotonic() < deadline:
                for collector in values:
                    collector.cpu_ns()
                time.sleep(
                    0.1 if deadline is None else min(0.1, max(0, deadline - time.monotonic()))
                )
        except KeyboardInterrupt:
            interrupted = True
        end = time.monotonic_ns()
        errors = []
        for collector in reversed(values):
            try:
                collector.stop()
            except Exception as exc:
                errors.append(exc)
        if errors:
            raise errors[0]
        return dict(
            start_ns=start,
            end_ns=end,
            stop_reason='signal' if interrupted else 'duration',
            collectors={name: collector.result() for name, collector in collectors.items()},
        )
    finally:
        errors = []
        for collector in reversed(values):
            try:
                collector.close()
            except Exception as exc:
                errors.append(exc)
        if errors:
            raise errors[0]
