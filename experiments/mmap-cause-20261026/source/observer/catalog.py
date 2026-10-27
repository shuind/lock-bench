"""Resolve public selections to independent backend products."""

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).resolve().parent
TARGETS = ('mmap', 'cgroup', 'fork')
DEFAULT_METHODS = {'mmap': 'tracepoint', 'cgroup': 'fentry', 'fork': 'kprobe'}


@dataclass(frozen=True)
class Backend:
    id: str
    target: str
    method: str
    timer: bool
    programs: tuple
    directory: Path

    @property
    def binary(self):
        return self.directory / 'dist/observer'

    @property
    def object(self):
        return self.directory / 'dist/observer.bpf.o'

    @property
    def timer_object(self):
        return self.directory / 'dist/observer.timer.bpf.o'


def backends():
    result = {}
    for path in sorted(ROOT.glob('*/*/backend.json')):
        data = json.loads(path.read_text(encoding='utf-8'))
        item = Backend(**{**data, 'programs': tuple(data['programs']), 'directory': path.parent})
        result[item.id] = item
    return result


@dataclass(frozen=True)
class Selection:
    backend: Backend
    observe: bool
    collect: str
    timeout: str
    threshold_ns: int
    poll_ms: int
    rw: str
    duration: Optional[float]
    object: Path
    event_counts: bool = True

    def command(self):
        command = [
            str(self.backend.binary),
            'run',
            '--observe',
            'on' if self.observe else 'off',
            '--collect',
            self.collect,
            '--event-counts',
            'on' if self.event_counts else 'off',
            '--timeout',
            self.timeout,
            '--threshold-ns',
            str(self.threshold_ns),
            '--poll-ms',
            str(self.poll_ms),
            '--rw',
            self.rw,
            '--object',
            str(self.object),
        ]
        if self.duration is not None:
            command += ['--duration', str(self.duration)]
        return command


def targets(value):
    items = list(TARGETS) if value == 'all' else value.split(',')
    if not items or len(items) != len(set(items)) or any(item not in TARGETS for item in items):
        raise ValueError('Invalid --target list')
    return items


def select_products(target='all', scheme=None, mmap_scheme=None, cgroup_scheme=None):
    """Build/inspect can select every method, or one per selected object."""
    selected = targets(target)
    overrides = {'mmap': mmap_scheme, 'cgroup': cgroup_scheme}
    if any(value and key not in selected for key, value in overrides.items()):
        raise ValueError('Method override for a disabled target')
    items = list(backends().values())
    result = []
    for name in selected:
        method = 'kprobe' if name == 'fork' else overrides.get(name) or scheme
        matches = [
            item for item in items if item.target == name and (not method or item.method == method)
        ]
        if not matches:
            raise ValueError(f'{name} does not support {method}')
        result.extend(matches)
    return result


def resolve(args):
    selected = targets(args.target)
    products = backends()
    if not 1 <= args.poll_ms <= 60000:
        raise ValueError('--poll-ms must be 1..60000')
    if getattr(args, 'object', None) and len(selected) != 1:
        raise ValueError('--object requires a single --target')
    result = []
    for target in TARGETS:
        if target not in selected:
            if any(
                getattr(args, target + '_' + field, None) is not None
                for field in ('scheme', 'collect', 'timeout', 'event_counts')
            ):
                raise ValueError('Override for disabled target: ' + target)
            continue
        method = (
            'kprobe'
            if target == 'fork'
            else getattr(args, target + '_scheme', None) or args.scheme or DEFAULT_METHODS[target]
        )
        backend = products.get(target + '/' + method)
        if not backend:
            raise ValueError(f'{target} does not support {method}')
        collect = getattr(args, target + '_collect', None) or args.collect
        event_counts = (
            getattr(args, target + '_event_counts', None)
            or getattr(args, 'event_counts', 'on')
        ) == 'on'
        timeout = getattr(args, target + '_timeout', None) or args.timeout
        if collect == 'count' and not event_counts:
            raise ValueError('collect=count requires --event-counts on')
        if timeout != 'none' and collect == 'count':
            raise ValueError('Timeout detection requires state or stack')
        if timeout == 'timer' and not backend.timer:
            raise ValueError(f'{backend.id} has no timer support on the validated kernel')
        result.append(
            Selection(
                backend,
                args.observe == 'on',
                collect,
                timeout,
                args.threshold_ns,
                args.poll_ms,
                args.rw,
                getattr(args, 'duration', None),
                getattr(args, 'object', None)
                or (backend.timer_object if timeout == 'timer' else backend.object),
                event_counts,
            )
        )
    return result
