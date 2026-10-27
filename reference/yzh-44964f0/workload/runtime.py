"""Preparation/start/result/finish protocol, independent of any observer."""

import ctypes
import json
import os
import resource
import socket
import time


def clock(pid):
    value = ctypes.c_int()
    result = ctypes.CDLL(None).clock_getcpuclockid(int(pid), ctypes.byref(value))
    if result:
        raise OSError(result, os.strerror(result))
    return value.value


class Session:
    def __init__(self, args):
        self.args = args
        self.children = []
        self.socket = None
        self.stream = None
        if 'LOCKBENCH_WORKLOAD_FD' in os.environ:
            self.socket = socket.socket(fileno=int(os.environ['LOCKBENCH_WORKLOAD_FD']))
            self.stream = self.socket.makefile('rwb', buffering=0)

    def watch(self, process):
        self.children.append(process)
        return process

    def cpu(self):
        value = time.process_time_ns()
        usage = resource.getrusage(resource.RUSAGE_CHILDREN)
        value += int((usage.ru_utime + usage.ru_stime) * 1e9)
        for child in self.children:
            if child.poll() is None:
                try:
                    value += time.clock_gettime_ns(clock(child.pid))
                except (OSError, ProcessLookupError):
                    pass
        return value

    def send(self, value):
        line = (json.dumps(value) + '\n').encode()
        if self.stream:
            self.stream.write(line)
        else:
            print(line.decode().strip(), flush=True)

    def ready(self, **metadata):
        value = dict(phase='ready', pid=os.getpid(), workload=self.args.workload)
        value.update(metadata)
        self.send(value)
        if self.stream and self.stream.readline() != b'G\n':
            raise RuntimeError('Workload start command missing')
        self.cpu0 = self.cpu()
        self.start_ns = time.monotonic_ns()

    def result(self, operations, unit='operations', **metrics):
        end = time.monotonic_ns()
        result = dict(
            phase='result',
            workload=self.args.workload,
            verified=True,
            operations=operations,
            unit=unit,
            wall_ns=end - self.start_ns,
            cpu_ns=self.cpu() - self.cpu0,
            metrics=metrics,
        )
        self.send(result)
        if self.stream and self.stream.readline() != b'F\n':
            raise RuntimeError('Workload finish command missing')
        return result

    def close(self):
        for child in reversed(self.children):
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=5)
                except TimeoutError:
                    child.kill()
                    child.wait()
                except __import__('subprocess').TimeoutExpired:
                    child.kill()
                    child.wait()
        if self.stream:
            self.stream.close()
            self.socket.close()
