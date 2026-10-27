"""Native backend adapter: private control channel, CPU clock and JSON export."""

import ctypes
import json
import os
from pathlib import Path
import select
import signal
import socket
import subprocess
import time

from .catalog import Selection


class NativeObserver:
    def __init__(self, selection: Selection, directory: Path, live=False):
        self.selection = selection
        self.directory = directory
        self.live = live
        self.process = self.channel = self.clock = None
        self.handles = []
        self.value = None
        self.started = self.stop_requested = False

    def _expect(self, expected, timeout):
        if (
            not select.select([self.channel], [], [], timeout)[0]
            or self.channel.recv(1) != expected
        ):
            raise RuntimeError(
                f'{self.selection.backend.id}: control failed; see {self.directory / "observer.log"}'
            )

    def prepare(self):
        if self.process is not None:
            raise RuntimeError('Observer already prepared')
        if not self.selection.backend.binary.exists():
            raise FileNotFoundError(f'Build observer {self.selection.backend.id} first')
        if self.selection.observe and not self.selection.object.exists():
            raise FileNotFoundError(str(self.selection.object))
        self.directory.mkdir(parents=True, exist_ok=True)
        self.channel, child = socket.socketpair()
        output = (self.directory / 'observer.json').open('w')
        self.handles.append(output)
        log = None
        if not self.live:
            log = (self.directory / 'observer.log').open('w')
            self.handles.append(log)
        try:
            self.process = subprocess.Popen(
                self.selection.command(),
                env=dict(os.environ, LOCKBENCH_CONTROL_FD=str(child.fileno())),
                pass_fds=(child.fileno(),),
                stdout=output,
                stderr=log,
                start_new_session=True,
            )
        finally:
            child.close()
        self._expect(b'R', 30)
        value = ctypes.c_int()
        error = ctypes.CDLL(None).clock_getcpuclockid(self.process.pid, ctypes.byref(value))
        if error:
            raise OSError(error, os.strerror(error))
        self.clock = value.value

    def start(self):
        if self.started or not self.process:
            raise RuntimeError('Observer is not prepared or already started')
        self.channel.sendall(b'G')
        self._expect(b'A', 5)
        self.started = True

    def cpu_ns(self):
        if self.clock is None:
            raise RuntimeError('Observer not prepared')
        return time.clock_gettime_ns(self.clock)

    def request_stop(self):
        if self.stop_requested:
            return
        if not self.started:
            raise RuntimeError('Observer has not started')
        self.channel.sendall(b'D')
        self.stop_requested = True

    def finish_stop(self):
        code = self.process.wait(timeout=15)
        for handle in self.handles:
            handle.flush()
        self.value = json.loads((self.directory / 'observer.json').read_text(encoding='utf-8'))
        if code or self.value.get('error') or self.value.get('cleanup_error'):
            raise RuntimeError(
                f'{self.selection.backend.id}: collection failed; see {self.directory}'
            )
        if self.value.get('stop_reason') != 'controller':
            raise RuntimeError(
                f'{self.selection.backend.id}: observation ended before the measurement window'
            )

    def stop(self):
        self.request_stop()
        self.finish_stop()

    def result(self):
        if self.value is None:
            raise RuntimeError('Observer result is not ready')
        return self.value

    def close(self):
        if self.process and self.process.poll() is None:
            try:
                os.killpg(self.process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(self.process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                self.process.wait(timeout=5)
        if self.channel:
            self.channel.close()
        for handle in self.handles:
            handle.close()


class CompositeObserver:
    """The same public contract, backed by several independent native processes."""

    def __init__(self, observers):
        self.observers = observers

    def prepare(self):
        try:
            for observer in self.observers:
                observer.prepare()
        except BaseException:
            self.close()
            raise

    def start(self):
        try:
            for observer in self.observers:
                observer.start()
        except BaseException:
            self.close()
            raise

    def cpu_ns(self):
        return sum(observer.cpu_ns() for observer in self.observers)

    def stop(self):
        # Close every admission gate before waiting for any drain/export.
        errors = []
        for observer in self.observers:
            try:
                observer.request_stop()
            except Exception as exc:
                errors.append(exc)
        for observer in self.observers:
            try:
                observer.finish_stop()
            except Exception as exc:
                errors.append(exc)
        if errors:
            raise errors[0]

    def result(self):
        objects = {
            observer.selection.backend.target: observer.result() for observer in self.observers
        }
        return dict(
            version=4,
            mode='run',
            scope='host',
            targets=list(objects),
            objects=objects,
            observe=any(item['observe'] for item in objects.values()),
            error=0,
            cleanup_error=0,
            stop_reason='controller',
        )

    def close(self):
        for observer in reversed(self.observers):
            observer.close()
