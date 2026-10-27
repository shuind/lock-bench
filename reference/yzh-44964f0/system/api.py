"""Host metrics adapter implementing the shared collector lifecycle."""

from .metrics import SystemMonitor
from session import CollectorFactory


class SystemCollector:
    def __init__(self, monitor):
        self.monitor = monitor

    def prepare(self):
        pass

    def start(self):
        self.monitor.start()

    def cpu_ns(self):
        return self.monitor.sampling_cpu_ns

    def stop(self):
        self.monitor.stop()

    def result(self):
        return self.monitor.result()

    def close(self):
        self.monitor.close()


def factory(interval_ms=1000, output=None, live=False, filename=None) -> CollectorFactory:
    def create(directory):
        destination = output or (directory / filename if filename else None)
        return SystemCollector(SystemMonitor(interval_ms, destination, live=live))

    return create
