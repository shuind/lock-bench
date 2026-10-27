"""Run prepared workloads against the same standalone host-wide observer."""

import json
import os
from pathlib import Path
import random
import select
import signal
import socket
import subprocess
import sys
import tempfile
import time

from workload.registry import ROOT, resolve
from session import CollectorFactory
from .resources import Resources, host_snapshot, own_directory


def dump(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


WORK_FLAGS = (
    'duration',
    'operations',
    'concurrency',
    'file_mib',
    'anon_mib',
    'file_threads',
    'memory_threads',
    'run_timeout',
    'project',
)


def flags(args, names):
    values = []
    for key in names:
        value = getattr(args, key, None)
        if value is not None:
            values += ['--' + key.replace('_', '-'), str(value)]
    return values


def receive(stream, timeout):
    if not select.select([stream], [], [], timeout)[0]:
        raise TimeoutError('Workload protocol timeout')
    line = stream.readline()
    if not line:
        raise RuntimeError('Workload exited before completing its protocol')
    return json.loads(line)


def stop(process):
    if process and process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)


def measure(
    args,
    directory,
    observe,
    observer_factory: CollectorFactory = None,
    system_factory: CollectorFactory = None,
):
    if observe and observer_factory is None:
        raise ValueError('An observer factory is required')
    directory.mkdir()
    own_directory(directory)
    resources = Resources(args).create()
    worker = observer = None
    wp = stream = None
    handles = []
    monitor = None
    try:
        wp, child = socket.socketpair()
        env = dict(os.environ, LOCKBENCH_WORKLOAD_FD=str(child.fileno()), **resources.environment())
        log = (directory / 'controller.log').open('w')
        handles.append(log)
        worker = subprocess.Popen(
            [
                sys.executable,
                str(ROOT / 'lockbench.py'),
                'workload',
                'run',
                '--workload',
                args.workload,
                '--workdir',
                str(directory),
                *flags(args, WORK_FLAGS),
            ],
            cwd=ROOT,
            env=env,
            pass_fds=(child.fileno(),),
            stdout=log,
            stderr=log,
            start_new_session=True,
        )
        child.close()
        stream = wp.makefile('rwb', buffering=0)
        ready = receive(stream, args.run_timeout)
        if ready.get('phase') != 'ready':
            raise RuntimeError('Workload not ready')
        if observe:
            observer = observer_factory(directory / 'observer')
            observer.prepare()
            observer.start()
        if system_factory:
            monitor = system_factory(directory)
            monitor.prepare()
        before = resources.snapshot()
        host_before = host_snapshot() if monitor else None
        if monitor:
            monitor.start()
        observer_cpu0 = observer.cpu_ns() if observer else 0
        controller_cpu0 = time.process_time_ns()
        begin = time.monotonic_ns()
        stream.write(b'G\n')
        value = receive(stream, args.run_timeout)
        if (
            value.get('phase') != 'result'
            or not value.get('verified')
            or not value.get('operations')
        ):
            raise RuntimeError('Invalid workload result')
        end = time.monotonic_ns()
        controller_cpu = time.process_time_ns() - controller_cpu0
        observer_cpu = observer.cpu_ns() - observer_cpu0 if observer else 0
        after = resources.snapshot()
        host_after = host_snapshot() if monitor else None
        if monitor:
            monitor.stop()
        if observer:
            observer.stop()
            observation = observer.result()
            dump(directory / 'observer.json', observation)
            if observation.get('error') or observation.get('cleanup_error'):
                raise RuntimeError('Observer returned an error')
            objects = observation.get('objects', {'one': observation})
            for item in objects.values():
                errors = {
                    k: item['counters'][k]
                    for k in (
                        'state_errors',
                        'pair_errors',
                        'stack_errors',
                        'timer_errors',
                        'ring_dropped',
                    )
                    if item['counters'][k]
                }
                if item.get('mmap_cleanup_errors'):
                    errors['mmap_cleanup_errors'] = item['mmap_cleanup_errors']
                if errors or item['retprobe_misses'] or item['live_poll_errors']:
                    raise RuntimeError('Observer sampling/tracking error: ' + repr(errors))
        else:
            observation = None
        cpu = after['cpu_ns'] - before['cpu_ns'] if 'cpu_ns' in before else value['cpu_ns']
        result = dict(
            schema_version=1,
            workload=args.workload,
            observe=observe,
            ready=ready,
            result=value,
            workload_cpu_ns=cpu,
            cpu_scope=(
                'workload cgroup incl. descendants'
                if 'cpu_ns' in before
                else 'workload reported self+children CPU'
            ),
            observer_cpu_ns=observer_cpu,
            controller_cpu_ns=controller_cpu,
            wall_ns=end - begin,
            before=before,
            after=after,
            host_before=host_before,
            host_after=host_after,
            observation=observation,
            system=monitor.result() if monitor else dict(enabled=False, scope='host'),
        )
        stream.write(b'F\n')
        if worker.wait(timeout=30):
            raise RuntimeError('Workload cleanup failed')
        dump(directory / 'measurement.json', result)
        return result
    except BaseException as exc:
        dump(directory / 'failure.json', {'error': repr(exc)})
        raise
    finally:
        if monitor:
            monitor.close()
        stop(worker)
        if observer:
            observer.close()
        if stream:
            stream.close()
        if wp:
            wp.close()
        for handle in handles:
            handle.close()
        resources.close()


def run(args, observer_factory: CollectorFactory = None, system_factory: CollectorFactory = None):
    if sys.platform != 'linux':
        raise RuntimeError('Experiments require Linux')
    resolve(args)
    if args.observe == 'on' and os.geteuid() != 0:
        raise PermissionError('Use sudo to load BPF programs')
    base = args.output or ROOT / 'bench/experiments' / args.workload / 'results'
    base.mkdir(parents=True, exist_ok=True)
    own_directory(base)
    out = Path(tempfile.mkdtemp(prefix=time.strftime('run-%Y%m%d-%H%M%S-'), dir=base))
    own_directory(out)
    parameters = {
        k: str(v) if isinstance(v, Path) else v for k, v in vars(args).items() if k != 'handler'
    }
    parameters.update(
        observer_scope='host',
        measurement='ready/go/result/finish; preparation and cleanup excluded',
        implementation='observer + pure workload + shared bench runner',
    )
    dump(out / 'parameters.json', parameters)
    print('RESULTS: ' + str(out), flush=True)
    rng = random.Random(args.seed)
    try:
        for repeat in range(1, args.repeats + 1):
            order = [False, True] if args.observe == 'on' else [False]
            rng.shuffle(order)
            for observe in order:
                label = f'round-{repeat}-' + ('probe' if observe else 'baseline')
                row = measure(args, out / label, observe, observer_factory, system_factory)
                row.update(repeat=repeat, label=label)
                with (out / 'raw.jsonl').open('a', encoding='utf-8') as stream:
                    stream.write(json.dumps(row) + '\n')
                print(
                    f'{label}: CPU={row["workload_cpu_ns"]/1e6:.2f} ms; wall={row["wall_ns"]/1e6:.2f} ms; operations={row["result"]["operations"]}',
                    flush=True,
                )
        from .analysis import analyze

        analyze(out)
        dump(out / 'completed.json', {'status': 'complete', 'repeats': args.repeats})
        print('COMPLETE: ' + str(out), flush=True)
    except BaseException as exc:
        dump(out / 'failure.json', {'error': repr(exc)})
        raise
    return 0
