"""Kbuild header export: no probes A, exact empty hooks B, yzh collection C."""
import argparse
import csv
import ctypes
from dataclasses import replace
import json
import math
import os
from pathlib import Path
import pwd
import random
import shutil
import signal
import socket
import statistics
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
SOURCE = HERE / 'source'
KERNEL = HERE / 'kernel'
sys.path.insert(0, str(SOURCE))
from observer.catalog import backends, Selection
from observer.native import NativeObserver

METHODS = ('tracepoint', 'raw', 'fentry', 'kprobe')
ERRORS = ('state_errors', 'pair_errors', 'timer_errors', 'ring_dropped', 'mm_duplicate', 'mm_aborted', 'stack_errors')

def dump(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')

def status(message):
    print(time.strftime('%H:%M:%S'), message, flush=True)

def clock(pid):
    value = ctypes.c_int()
    error = ctypes.CDLL(None).clock_getcpuclockid(pid, ctypes.byref(value))
    if error:
        raise OSError(error, os.strerror(error))
    return value.value

def work_command(args, destination):
    return ['make', '-s', '-C', str(KERNEL), 'ARCH=arm64', '-j' + str(args.jobs),
            'headers_install', 'INSTALL_HDR_PATH=' + str(destination)]

def summary(values):
    mid = statistics.median(values)
    mad = statistics.median(abs(x - mid) for x in values)
    return dict(median=mid, mad=mad, madn=mad / 0.6744897501960817, min=min(values), max=max(values), rounds=values)

def analyze(out, rows, args):
    reports = []
    for method in METHODS:
        groups = []
        for repeat in range(args.repeats):
            values = {r['arm']: r for r in rows if r['method'] == method and r['repeat'] == repeat and r['phase'] == 'timing'}
            if len(values) == 3:
                groups.append(values)
        if not groups:
            continue
        report = dict(method=method, complete_blocks=len(groups), metrics={})
        for metric in ('wall_s', 'workload_cpu_s', 'observer_cpu_s', 'combined_cpu_s'):
            result = {arm: summary([g[arm][metric] for g in groups]) for arm in 'ABC'}
            for name, first, second in [('attachment_B-A', 'B', 'A'), ('collection_C-B', 'C', 'B'), ('total_C-A', 'C', 'A')]:
                result[name] = summary([g[first][metric] - g[second][metric] for g in groups])
                result[name + '_pct'] = summary([(g[first][metric] - g[second][metric]) / g[second][metric] * 100
                                                 for g in groups if g[second][metric] > 0]) if any(g[second][metric] > 0 for g in groups) else None
            report['metrics'][metric] = result
        reports.append(report)
    dump(out / 'summary.json', reports)
    with (out / 'rounds.csv').open('w', newline='') as f:
        keys = ['method', 'repeat', 'arm', 'phase', 'wall_s', 'workload_cpu_s', 'observer_cpu_s', 'controller_cpu_s', 'combined_cpu_s', 'headers', 'read_start', 'write_start', 'total_read_start', 'total_write_start']
        writer = csv.DictWriter(f, keys, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(rows)
    lines = ['Kbuild headers_install; yzh collector; all values in seconds.',
             f'jobs={args.jobs}; collect={args.collect}; timeout={args.timeout}; all-host read+write observation.',
             'Columns are medians of arms and separately medians of paired differences; they need not add exactly.',
             'method | metric | A | B | B-A | C-B | C-A | C | total delta MADN']
    for r in reports:
        for metric in ('wall_s', 'workload_cpu_s', 'combined_cpu_s'):
            d = r['metrics'][metric]
            nums = [d[x]['median'] for x in ('A', 'B', 'attachment_B-A', 'collection_C-B', 'total_C-A', 'C')]
            lines.append(r['method'] + ' | ' + metric + ' | ' + ' | '.join(f'{n:.6f}' for n in nums) + f" | {d['total_C-A']['madn']:.6f}")
    (out / 'SUMMARY.txt').write_text('\n'.join(lines) + '\n')

def measure(out, args, method, arm, repeat, phase):
    folder = out / f'{phase}-{method}-{repeat + 1}-{arm}'
    folder.mkdir()
    # headers_install caches sanitized UAPI headers in kernel/usr/include.
    # Removing only INSTALL_HDR_PATH would accidentally benchmark rsync alone.
    generated = (KERNEL / 'usr/include').resolve()
    if not generated.is_relative_to(KERNEL.resolve()) or KERNEL.parent != HERE:
        raise RuntimeError('Unexpected private kernel directory')
    if generated.exists():
        shutil.rmtree(generated)
    uid = int(os.environ.get('SUDO_UID', os.getuid()))
    gid = pwd.getpwuid(uid).pw_gid
    destination = folder / 'headers'
    destination.mkdir()
    # The measured make and descendants run as the ordinary account in every arm.
    if os.geteuid() == 0:
        os.chown(folder, uid, gid)
        os.chown(destination, uid, gid)
    backend = backends()['mmap/' + method]
    obj = HERE / f'empty-{method}.bpf.o' if arm == 'B' else backend.object
    selection = Selection(backend, arm != 'A', args.collect, args.timeout, 100000000, 100, 'both', None, obj)
    observer = NativeObserver(selection, folder / 'collector')
    process = None
    try:
        observer.prepare()
        observer.start()
        observer_before = observer.cpu_ns()
        controller_before = time.process_time_ns()
        command = work_command(args, destination)
        def ordinary_account():
            os.setsid()
            if os.geteuid() == 0:
                os.setgroups([])
                os.setgid(gid)
                os.setuid(uid)
        env = dict(os.environ, LC_ALL='C')
        env['PATH'] = str(HERE / 'tools/usr/bin') + os.pathsep + env['PATH']
        for name in ('MAKEFLAGS', 'MFLAGS', 'MAKELEVEL', 'KBUILD_OUTPUT'):
            env.pop(name, None)
        start = time.perf_counter_ns()
        with (folder / 'make.log').open('w') as log:
            parent_gate,child_gate=socket.socketpair()
            process = subprocess.Popen([str(HERE/'gate-exec'),*command], stdout=log, stderr=subprocess.STDOUT,
                    env=dict(env,DIAGNOSTIC_GATE_FD=str(child_gate.fileno())),pass_fds=(child_gate.fileno(),),preexec_fn=ordinary_account)
            child_gate.close();parent_gate.settimeout(15)
            if parent_gate.recv(1)!=b'R':raise RuntimeError('Kbuild gate not ready')
            observer.set_profile_root(process.pid,True)
            if os.environ.get('DIAGNOSTIC_WORKLOAD_CPUS'):
                os.sched_setaffinity(process.pid,{int(x)for x in os.environ['DIAGNOSTIC_WORKLOAD_CPUS'].split(',')})
            parent_gate.sendall(b'G');parent_gate.close()
            deadline = time.monotonic() + 300
            while True:
                pid, exit_status, usage = os.wait4(process.pid, os.WNOHANG)
                if pid:
                    process.returncode = os.waitstatus_to_exitcode(exit_status)
                    break
                if time.monotonic() >= deadline:
                    raise TimeoutError('headers_install exceeded 300s')
                time.sleep(0.005)
        wall = (time.perf_counter_ns() - start) / 1e9
        observer_cpu = (observer.cpu_ns() - observer_before) / 1e9
        controller_cpu = (time.process_time_ns() - controller_before) / 1e9
        observer.stop()
        observed = observer.result()
        if process.returncode:
            raise RuntimeError('headers_install failed: ' + (folder / 'make.log').read_text()[-3500:])
        headers = list((destination / 'include').rglob('*.h'))
        if len(headers) < 500 or not (destination / 'include/linux/bpf.h').is_file():
            raise RuntimeError('UAPI export did not produce the expected files')
        c = observed['counters']
        failures = {k: c.get(k, 0) for k in ERRORS if c.get(k, 0)}
        if observed.get('retprobe_misses'):
            failures['retprobe_misses'] = observed['retprobe_misses']
        if observed.get('mmap_cleanup_errors'):
            failures['mmap_cleanup_errors'] = observed['mmap_cleanup_errors']
        cpu = usage.ru_utime + usage.ru_stime
        row = dict(method=method, arm=arm, repeat=repeat, phase=phase, wall_s=wall,
                   workload_cpu_s=cpu, observer_cpu_s=observer_cpu, controller_cpu_s=controller_cpu,
                   combined_cpu_s=cpu + observer_cpu + controller_cpu, headers=len(headers),
                   voluntary_switches=usage.ru_nvcsw,involuntary_switches=usage.ru_nivcsw,
                   header_bytes=sum(p.stat().st_size for p in headers), command=command,
                   read_start=c.get('match_read_start', 0), write_start=c.get('match_write_start', 0),
                   total_read_start=c.get('total_read_start', 0), total_write_start=c.get('total_write_start', 0),
                   errors=failures, observer=observed)
        dump(folder / 'measurement.json', row)
        if failures:
            raise RuntimeError('Collection validation failed; see measurement.json: ' + str(failures))
        if arm == 'C' and row['read_start'] + row['write_start'] == 0:
            raise RuntimeError('No matching mmap lock acquisitions')
        if arm == 'B' and any(c.values()):
            raise RuntimeError('Empty callbacks unexpectedly changed counters')
        status(f'{phase} {method}/{arm}: wall={wall:.3f}s; workload CPU={cpu:.3f}s; collector CPU={observer_cpu:.4f}s; read/write={row["read_start"]}/{row["write_start"]}')
        return row
    finally:
        if process and process.returncode is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            process.wait()
        observer.close()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--jobs', type=int, default=1)
    parser.add_argument('--repeats', type=int, default=7)
    parser.add_argument('--collect', choices=('count', 'state', 'stack'), default='stack')
    parser.add_argument('--timeout', choices=('none', 'poll'), default='none')
    parser.add_argument('--baseline-only', action='store_true')
    args = parser.parse_args()
    if args.jobs < 1 or args.repeats < 1 or (args.collect == 'count' and args.timeout != 'none'):
        parser.error('Invalid jobs, repeats or count/poll combination')
    if os.geteuid() and not args.baseline_only:
        raise SystemExit('Run with sudo to load BPF probes')
    if not (HERE / 'preflight.json').exists():
        raise SystemExit('Run prepare_remote.py first')
    existing = []
    for path in Path('/proc').glob('[0-9]*/cmdline'):
        try:
            command = path.read_bytes().split(b'\0')
            if command and Path(os.fsdecode(command[0])).name == 'observer' and b'--observe' in command:
                index = command.index(b'--observe')
                if command[index + 1] == b'on':
                    existing.append(path.parent.name)
        except (OSError, IndexError):
            continue
    if existing:
        raise SystemExit('Other observers are running; stop them first. PIDs: ' + ', '.join(existing))
    out = Path(tempfile.mkdtemp(prefix=time.strftime('results-%Y%m%d-%H%M%S-'), dir=HERE))
    uid = int(os.environ.get('SUDO_UID', os.getuid()))
    os.chown(out, uid, pwd.getpwuid(uid).pw_gid)
    out.chmod(0o755)
    status('RESULTS: ' + str(out))
    stats_path = Path('/proc/sys/kernel/bpf_stats_enabled')
    before = stats_path.read_text().strip()
    dump(out / 'metadata.json', dict(config=vars(args), kernel=os.uname().release, machine=os.uname().machine,
                                    bpf_stats_enabled=before, source_commit='44964f0',
                                    clock='wall=monotonic; workload=wait4(make) user+system incl. reaped descendants; collector=process CPU clock',
                                    kernel_source=str(KERNEL), empty='same named hooks, return 0 only; unused maps retained for identical loader',
                                    warmup='host tools/arch-generated headers prepared; sanitized usr/include deleted before EVERY run; no drop_caches',
                                    screenshot_equivalence='not established: original units, jobs, source and collection configuration not provided'))
    rows = []
    if args.baseline_only:
        rows.append(measure(out, args, 'tracepoint', 'A', 0, 'baseline-check'))
        dump(out / 'rows.json', rows)
        status('BASELINE_ONLY_PASS')
        return
    # Verify all exact hook sets and complete collection before long timing.
    for method in METHODS:
        for arm in ('B', 'C'):
            measure(out, args, method, arm, 0, 'validation')
    rng = random.Random(20261026)
    schedule = []
    for repeat in range(args.repeats):
        methods = list(METHODS)
        rng.shuffle(methods)
        for method in methods:
            arms = list('ABC')
            rng.shuffle(arms)
            schedule.append(dict(repeat=repeat, method=method, order=arms))
    dump(out / 'schedule.json', schedule)
    for block in schedule:
        for arm in block['order']:
            rows.append(measure(out, args, block['method'], arm, block['repeat'], 'timing'))
            dump(out / 'rows.json', rows)
            analyze(out, rows, args)
    if stats_path.read_text().strip() != before:
        raise RuntimeError('bpf_stats_enabled changed during the experiment')
    dump(out / 'completed.json', dict(formal_runs=len(rows), checks='PASS'))
    status('KBUILD_REPRO_COMPLETE')
    print((out / 'SUMMARY.txt').read_text(), flush=True)

if __name__ == '__main__':
    main()
