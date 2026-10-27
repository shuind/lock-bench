"""Read-only host metrics, independent of BPF and development workloads."""

from collections import deque
import json
import math
from pathlib import Path
import threading
import time
from logutil import log_line

SOURCES = ('stat', 'meminfo', 'loadavg', 'pressure/cpu', 'pressure/memory', 'pressure/io')
CPU_FIELDS = ('user', 'nice', 'system', 'idle', 'iowait', 'irq', 'softirq', 'steal')


def snapshot(proc=Path('/proc')):
    """Raw boundary snapshot retained for experiment consumers."""
    result = {'monotonic_ns': time.monotonic_ns()}
    for name in SOURCES:
        try:
            result[name] = (proc / name).read_text()
        except OSError as exc:
            result.setdefault('read_errors', {})[name] = str(exc)
    return result


def cpu_delta(before, after):
    if before is None or after is None:
        return None
    values = {name: after[name] - before[name] for name in CPU_FIELDS}
    total = sum(values.values())
    if total <= 0 or any(value < 0 for value in values.values()):
        return None
    result = {name + '_percent': value * 100 / total for name, value in values.items()}
    result['busy_percent'] = 100 * (total - values['idle'] - values['iowait']) / total
    return result


class Reader:
    def __init__(self, proc=Path('/proc')):
        self.proc = proc
        self.previous = None

    def read(self):
        started = time.monotonic_ns()
        raw = snapshot(self.proc)
        sample = dict(
            monotonic_ns=raw['monotonic_ns'],
            wall_time_ns=time.time_ns(),
            cpu=None,
            memory=None,
            load=None,
            psi={},
            errors=dict(raw.get('read_errors', {})),
        )

        def parse(name, function):
            if name not in raw:
                return None
            try:
                return function(raw[name])
            except (ValueError, KeyError, IndexError) as exc:
                sample['errors'][name] = 'Invalid data: ' + str(exc)
                return None

        sample['cpu'] = parse('stat', self._cpu)
        sample['memory'] = parse('meminfo', self._memory)
        sample['load'] = parse('loadavg', self._load)
        for resource in ('cpu', 'memory', 'io'):
            sample['psi'][resource] = parse(
                'pressure/' + resource,
                lambda text, resource=resource: self._pressure(text, resource),
            )
        if self.previous:
            elapsed = sample['monotonic_ns'] - self.previous['monotonic_ns']
            sample['interval_ms'] = elapsed / 1e6
            old_cpu = self.previous['cpu']
            if sample['cpu'] is not None:
                sample['cpu']['utilization'] = cpu_delta(
                    old_cpu['ticks'] if old_cpu else None, sample['cpu']['ticks']
                )
            if elapsed > 0:
                for resource, pressure in sample['psi'].items():
                    old = self.previous['psi'].get(resource)
                    for kind, value in (pressure or {}).items():
                        previous = (old or {}).get(kind)
                        delta = value['total_us'] - previous['total_us'] if previous else -1
                        value['interval_percent'] = delta * 100000 / elapsed if delta >= 0 else None
        else:
            sample['interval_ms'] = None
        sample['read_duration_ns'] = time.monotonic_ns() - started
        self.previous = sample
        return sample

    @staticmethod
    def _cpu(text):
        lines = text.splitlines()
        fields = next((line.split()[1:] for line in lines if line.startswith('cpu ')), [])
        if len(fields) < 4:
            raise ValueError('Missing aggregate CPU counters')
        ticks = [int(value) for value in fields[:8]]
        ticks += [0] * (8 - len(ticks))
        if min(ticks) < 0:
            raise ValueError('Negative CPU counter')
        return dict(
            ticks=dict(zip(CPU_FIELDS, ticks)),
            utilization=None,
            logical_cpus=sum(
                line.split()[0][3:].isdigit() for line in lines if line.startswith('cpu')
            ),
        )

    @staticmethod
    def _memory(text):
        values = {}
        for line in text.splitlines():
            key, rest = line.split(':', 1)
            parts = rest.split()
            values[key] = int(parts[0]) * (1024 if len(parts) > 1 and parts[1] == 'kB' else 1)
        if values['MemTotal'] <= 0:
            raise ValueError('Invalid memory total')
        names = dict(
            total_bytes='MemTotal',
            available_bytes='MemAvailable',
            free_bytes='MemFree',
            buffers_bytes='Buffers',
            cached_bytes='Cached',
            swap_total_bytes='SwapTotal',
            swap_free_bytes='SwapFree',
        )
        result = {name: values.get(field) for name, field in names.items()}
        available = result['available_bytes']
        result['used_bytes'] = result['total_bytes'] - available if available is not None else None
        result['used_percent'] = (
            100 * result['used_bytes'] / result['total_bytes'] if available is not None else None
        )
        total, free = result['swap_total_bytes'], result['swap_free_bytes']
        result['swap_used_bytes'] = total - free if total is not None and free is not None else None
        return result

    @staticmethod
    def _load(text):
        fields = text.split()
        averages = [float(value) for value in fields[:3]]
        if len(averages) != 3 or any(not math.isfinite(value) or value < 0 for value in averages):
            raise ValueError('Invalid load averages')
        runnable, tasks = map(int, fields[3].split('/'))
        return dict(
            zip(('load1', 'load5', 'load15'), averages), runnable_tasks=runnable, tasks=tasks
        )

    @staticmethod
    def _pressure(text, resource):
        result = {}
        for line in text.splitlines():
            kind, *fields = line.split()
            if kind not in ('some', 'full') or (resource == 'cpu' and kind == 'full'):
                continue
            values = dict(field.split('=', 1) for field in fields)
            result[kind] = {
                name + '_percent': float(values[name]) for name in ('avg10', 'avg60', 'avg300')
            }
            if any(not math.isfinite(value) or value < 0 for value in result[kind].values()):
                raise ValueError('Invalid pressure average')
            result[kind].update(total_us=int(values['total']), interval_percent=None)
            if result[kind]['total_us'] < 0:
                raise ValueError('Negative pressure total')
        if 'some' not in result:
            raise ValueError('Missing some pressure counters')
        return result


class SystemMonitor:
    """One periodic sampler per session; bounded export and optional full JSONL."""

    def __init__(self, interval_ms=1000, output=None, live=False, reader=None, capacity=3600):
        if not 100 <= interval_ms <= 60000:
            raise ValueError('--system-interval-ms must be 100..60000')
        self.interval_ms, self.output, self.live = interval_ms, output, live
        self.reader = reader or Reader()
        self.samples = deque(maxlen=capacity)
        self.samples_total = self.sampling_cpu_ns = 0
        self.first = self.last = self.thread = self.stream = None
        self.errors = {}
        self.done = threading.Event()
        self.started = self.stopped = False

    def _sample(self):
        cpu = time.thread_time_ns()
        value = self.reader.read()
        if self.first is None:
            self.first = value
        self.last = value
        self.samples.append(value)
        self.samples_total += 1
        if self.stream:
            try:
                self.stream.write(json.dumps(value) + '\n')
                self.stream.flush()
            except OSError as exc:
                self.errors['output'] = str(exc)
                failed = self.stream
                self.stream = None
                try:
                    failed.close()
                except OSError:
                    pass
        if self.live:
            if self.samples_total == 1:
                for source, reason in value['errors'].items():
                    log_line(
                        f'SYSTEM_UNAVAILABLE source={source} reason={reason}',
                        wall_time_ns=value['wall_time_ns'],
                    )

            def number(value):
                return 'n/a' if value is None else f'{value:.2f}'

            utilization = (value['cpu'] or {}).get('utilization') or {}
            pressure = {
                resource: ((data or {}).get('some') or {}).get('avg10_percent')
                for resource, data in value['psi'].items()
            }
            log_line(
                'SYSTEM '
                f'elapsed_s={(value["monotonic_ns"]-self.first["monotonic_ns"])/1e9:.3f} '
                f'cpu_busy_pct={number(utilization.get("busy_percent"))} '
                f'mem_used_pct={number((value["memory"] or {}).get("used_percent"))} '
                f'load1={number((value["load"] or {}).get("load1"))} '
                f'psi_cpu_some_avg10_pct={number(pressure.get("cpu"))} '
                f'psi_memory_some_avg10_pct={number(pressure.get("memory"))} '
                f'psi_io_some_avg10_pct={number(pressure.get("io"))}',
                wall_time_ns=value['wall_time_ns'],
            )
        self.sampling_cpu_ns += time.thread_time_ns() - cpu

    def _loop(self):
        next_sample = time.monotonic() + self.interval_ms / 1000
        try:
            while not self.done.wait(max(0, next_sample - time.monotonic())):
                self._sample()
                now = time.monotonic()
                next_sample += self.interval_ms / 1000
                if next_sample <= now:
                    next_sample = now + self.interval_ms / 1000
        except Exception as exc:
            self.errors['sampler'] = repr(exc)

    def start(self):
        if self.started:
            raise RuntimeError('System sampler already started')
        if self.output:
            self.output.parent.mkdir(parents=True, exist_ok=True)
            self.stream = self.output.open('w', encoding='utf-8')
        self.started = True
        self._sample()
        self.thread = threading.Thread(target=self._loop, name='system-metrics', daemon=True)
        self.thread.start()

    def stop(self):
        if not self.started or self.stopped:
            return
        self.done.set()
        if self.thread:
            self.thread.join(timeout=5)
            if self.thread.is_alive():
                raise RuntimeError('System sampler did not stop within 5 seconds')
        self.stopped = True
        self._sample()
        if self.stream:
            self.stream.close()
            self.stream = None

    def result(self):
        if not self.stopped:
            raise RuntimeError('System sampler result is not ready')
        first, last = self.first, self.last
        available = {name: last[name] is not None for name in ('cpu', 'memory', 'load')}
        available.update({'psi_' + name: value is not None for name, value in last['psi'].items()})
        return dict(
            enabled=True,
            scope='host',
            interval_ms=self.interval_ms,
            start_ns=first['monotonic_ns'],
            end_ns=last['monotonic_ns'],
            cpu_window=cpu_delta(
                (first['cpu'] or {}).get('ticks'), (last['cpu'] or {}).get('ticks')
            ),
            sampling_cpu_ns=self.sampling_cpu_ns,
            samples_total=self.samples_total,
            samples_retained=len(self.samples),
            samples_truncated=self.samples_total > len(self.samples),
            output=str(self.output) if self.output else None,
            errors=dict(self.errors),
            availability=available,
            source_errors=dict(last['errors']),
            samples=list(self.samples),
        )

    def close(self):
        self.done.set()
        if self.thread:
            self.thread.join(timeout=5)
        if self.stream and (self.thread is None or not self.thread.is_alive()):
            self.stream.close()
            self.stream = None
