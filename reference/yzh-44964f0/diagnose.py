#!/usr/bin/env python3
"""Short CPU attribution window for running lockbench observers (stdlib only)."""

import argparse
import ctypes
import errno
import json
import os
from pathlib import Path
import platform
import signal
import struct
import sys
import time


PROC = Path('/proc')


class ObservationChanged(RuntimeError):
    """The process/program set no longer matches the start of the window."""


def bpf(command, payload):
    number = {'x86_64': 321, 'aarch64': 280}.get(platform.machine())
    if number is None:
        raise OSError(errno.ENOSYS, 'Diagnostic syscall supports x86-64 and ARM64')
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    buffer = ctypes.create_string_buffer(payload)
    result = libc.syscall(
        ctypes.c_long(number),
        ctypes.c_int(command),
        ctypes.byref(buffer),
        ctypes.c_uint(len(payload)),
    )
    if result < 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    return result


def program_name(program_id):
    # BPF_PROG_GET_FD_BY_ID, then the stable first 80 bytes of bpf_prog_info.
    fd = bpf(13, struct.pack('=III', program_id, 0, 0))
    try:
        info = ctypes.create_string_buffer(80)
        bpf(15, struct.pack('=IIQ', fd, len(info), ctypes.addressof(info)))
        return info.raw[64:80].split(b'\0')[0].decode(errors='replace')
    finally:
        os.close(fd)


def fields(path):
    return dict(
        line.split(':', 1) for line in path.read_text().splitlines() if ':' in line
    )


def process(pid):
    tail = (PROC / str(pid) / 'stat').read_text().rsplit(')', 1)[1].split()
    return dict(
        start_ticks=int(tail[19]),
        parent=int(tail[1]),
        user_ticks=int(tail[11]),
        system_ticks=int(tail[12]),
    )


def command(pid):
    return [
        os.fsdecode(arg)
        for arg in (PROC / str(pid) / 'cmdline').read_bytes().split(b'\0')
        if arg
    ]


def sections(path):
    """Read ELF64 symbol/section names from the loaded .bpf.o, without libelf."""
    raw = path.read_bytes()
    if raw[:6] != b'\x7fELF\x02\x01':
        raise ValueError('Expected little-endian ELF64 BPF object')
    offset = struct.unpack_from('<Q', raw, 40)[0]
    size, count, strings_index = struct.unpack_from('<HHH', raw, 58)
    headers = [
        struct.unpack_from('<IIQQQQIIQQ', raw, offset + i * size) for i in range(count)
    ]

    def data(header):
        return raw[header[4] : header[4] + header[5]]

    def name(strings, offset):
        return strings[offset:].split(b'\0', 1)[0].decode(errors='replace')

    names = data(headers[strings_index])
    result = {}
    for header in headers:
        if header[1] != 2:  # SHT_SYMTAB
            continue
        strings, symbols = data(headers[header[6]]), data(header)
        for offset in range(0, len(symbols), header[9]):
            index, info, _, section, _, _ = struct.unpack_from(
                '<IBBHQQ', symbols, offset
            )
            if info & 15 != 2 or not 0 < section < count:
                continue
            hook = name(names, headers[section][0])
            if '/' not in hook:
                continue
            key = name(strings, index)[:15]  # Kernel BPF_OBJ_NAME_LEN includes the NUL.
            result[key] = (
                hook if key not in result or result[key] == hook else 'ambiguous'
            )
    return result


def discover(pids):
    found = {}
    paths = [PROC / str(pid) for pid in pids] if pids else PROC.glob('[0-9]*')
    for path in paths:
        try:
            args = command(int(path.name))
            if not args or Path(args[0]).name != 'observer' or 'run' not in args:
                continue
            if '--observe' not in args or args[args.index('--observe') + 1] != 'on':
                continue
            pid = int(path.name)
            item = process(pid)
            item['command'] = args
            item['role'] = 'observer'
            item['sections'] = {}
            try:
                obj = Path(args[args.index('--object') + 1])
                if not obj.is_absolute():
                    obj = (PROC / str(pid) / 'cwd' / obj).resolve()
                try:
                    item['sections'] = sections(obj)
                except (OSError, ValueError, IndexError, struct.error):
                    pass
                metadata = obj.parent.parent / 'backend.json'
                item['backend'] = json.loads(metadata.read_text())['id']
            except (OSError, ValueError, IndexError, KeyError):
                item['backend'] = 'observer'
            found[pid] = item
        except (OSError, ValueError, IndexError):
            if pids:
                raise RuntimeError(f'Cannot inspect native observer PID {path.name}')
    if not found:
        raise RuntimeError(
            'No running native observer found; start observation first, or use --pid NATIVE_PID'
        )
    # Include the Python controller (and its system sampling thread), when present.
    for item in list(found.values()):
        parent = item['parent']
        try:
            args = command(parent)
            if parent not in found and any(
                Path(arg).name == 'lockbench.py' for arg in args
            ):
                found[parent] = dict(
                    process(parent),
                    command=args,
                    role='controller',
                    backend='controller',
                )
        except (OSError, ValueError):
            pass
    return found


def programs(processes):
    found = {}
    for pid, item in processes.items():
        if item['role'] != 'observer':
            continue
        count = 0
        for path in (PROC / str(pid) / 'fdinfo').iterdir():
            try:
                data = fields(path)
            except FileNotFoundError:
                continue
            if 'prog_id' not in data or 'prog_type' not in data:
                continue
            count += 1
            program_id = int(data['prog_id'])
            if program_id in found:
                found[program_id]['owners'].append(pid)
                continue
            try:
                name = program_name(program_id)
            except OSError:
                name = f'program-{program_id}'
            found[program_id] = dict(
                name=name,
                path=str(path),
                backend=item['backend'],
                owners=[pid],
                hook=item['sections'].get(name),
                jited=bool(int(data['prog_jited'])) if 'prog_jited' in data else None,
            )
        if not count:
            raise RuntimeError(f'PID {pid} has no readable BPF program descriptors')
    return found


def snapshot(processes, progs):
    started = time.monotonic_ns()
    cpu = [
        int(value) for value in (PROC / 'stat').read_text().splitlines()[0].split()[1:9]
    ]
    tasks = {}
    for pid, initial in processes.items():
        try:
            item = process(pid)
        except OSError as exc:
            if exc.errno not in (errno.ENOENT, errno.ESRCH):
                raise
            raise ObservationChanged(
                f"{initial['backend']} {initial['role']} PID {pid} exited during diagnosis"
            ) from exc
        if item['start_ticks'] != initial['start_ticks']:
            raise ObservationChanged(
                f"{initial['backend']} PID {pid} was reused during diagnosis"
            )
        tasks[pid] = item
    runs = {}
    for program_id, item in progs.items():
        try:
            data = fields(Path(item['path']))
        except OSError as exc:
            if exc.errno not in (errno.ENOENT, errno.ESRCH):
                raise
            raise ObservationChanged(
                f"{item['backend']} BPF program {item['name']} descriptor closed during diagnosis"
            ) from exc
        if int(data.get('prog_id', '-1')) != program_id:
            raise ObservationChanged(
                f"{item['backend']} BPF program {item['name']} descriptor changed during diagnosis"
            )
        runs[program_id] = dict(
            time_ns=int(data['run_time_ns']) if 'run_time_ns' in data else None,
            count=int(data['run_cnt']) if 'run_cnt' in data else None,
            sampled_ns=time.monotonic_ns(),
        )
    return dict(
        start_ns=started,
        end_ns=time.monotonic_ns(),
        cpu=cpu,
        processes=tasks,
        programs=runs,
    )


def analyze(before, after, processes, progs, stats_enabled):
    hz = os.sysconf('SC_CLK_TCK')
    seconds = (after['start_ns'] - before['start_ns']) / 1e9
    cpu = [right - left for left, right in zip(before['cpu'], after['cpu'])]
    total = sum(cpu)
    if seconds <= 0 or total <= 0:
        raise RuntimeError('Invalid CPU sampling window')
    # Aggregate /proc/stat ticks give the actual system capacity in this window.
    capacity_s = total / hz
    rows = []
    for pid, item in processes.items():
        left, right = before['processes'][pid], after['processes'][pid]
        user_s = (right['user_ticks'] - left['user_ticks']) / hz
        system_s = (right['system_ticks'] - left['system_ticks']) / hz
        rows.append(
            dict(
                pid=pid,
                backend=item['backend'],
                role=item['role'],
                command=item['command'],
                user_cpu_s=user_s,
                system_cpu_s=system_s,
                cpu_s=user_s + system_s,
                cpu_cores=(user_s + system_s) / seconds,
                host_cpu_pct=(user_s + system_s) / capacity_s * 100,
            )
        )
    program_rows = []
    warnings = []
    for program_id, item in progs.items():
        left, right = before['programs'][program_id], after['programs'][program_id]
        available = stats_enabled and all(
            row[key] is not None
            for row in (left, right)
            for key in ('count', 'time_ns')
        )
        count = right['count'] - left['count'] if available else None
        runtime = right['time_ns'] - left['time_ns'] if available else None
        if available and (count < 0 or runtime < 0):
            raise RuntimeError(f'Runtime statistics reset for BPF program {program_id}')
        elapsed = (right['sampled_ns'] - left['sampled_ns']) / 1e9
        program_rows.append(
            dict(
                id=program_id,
                name=item['name'],
                backend=item['backend'],
                owners=item['owners'],
                hook=item.get('hook'),
                jited=item['jited'],
                stats_available=available,
                run_count=count,
                runtime_ns=runtime,
                runs_per_s=count / elapsed if available else None,
                average_ns=runtime / count if available and count else None,
                cpu_cores=runtime / 1e9 / elapsed if available else None,
                host_cpu_pct=runtime / 1e9 / capacity_s * 100 if available else None,
            )
        )
    if any(row['jited'] is False for row in program_rows):
        warnings.append(
            'Some BPF programs are not JIT compiled; inspect their cost first.'
        )
    if not all(row['stats_available'] for row in program_rows):
        warnings.append(
            'BPF runtime statistics are unavailable for some programs; missing values are not zero cost.'
        )
    return dict(
        duration_s=seconds,
        average_online_cpus=capacity_s / seconds,
        host_cpu_busy_pct=(total - cpu[3] - cpu[4]) / total * 100,
        host_cpu_user_pct=(cpu[0] + cpu[1]) / total * 100,
        host_cpu_system_pct=cpu[2] / total * 100,
        host_cpu_irq_pct=(cpu[5] + cpu[6]) / total * 100,
        processes=sorted(rows, key=lambda row: row['cpu_s'], reverse=True),
        programs=sorted(
            program_rows, key=lambda row: row['runtime_ns'] or 0, reverse=True
        ),
        warnings=warnings,
    )


def report(value):
    print(
        f"Status: {value['status']}; requested {value['requested_duration_s']:g}s; "
        f"measured {value.get('duration_s', 0):.2f}s"
    )
    if value.get('end_reason'):
        print(f"Reason: {value['end_reason']}")
    if not value['measurement_valid']:
        print(
            'No complete sampling interval is available; CPU values were not estimated.'
        )
        return
    print(
        f"Window {value['duration_s']:.2f}s; CPU capacity {value['average_online_cpus']:.1f} cores; "
        f"host busy {value['host_cpu_busy_pct']:.2f}%"
    )
    print(
        '\nProcesses: CPU includes their own syscalls and any BPF triggered by these processes.'
    )
    print(
        f"{'PID':>8} {'backend':<20} {'user s':>10} {'system s':>10} {'cores':>10} {'host %':>9}"
    )
    for row in value['processes']:
        print(
            f"{row['pid']:8d} {row['backend']:<20} {row['user_cpu_s']:10.3f} {row['system_cpu_s']:10.3f} "
            f"{row['cpu_cores']:10.4f} {row['host_cpu_pct']:9.4f}"
        )
    print(
        '\nBPF programs: all executions, including rejected events; sorted by measured runtime.'
    )
    print(
        f"{'backend':<20} {'program':<16} {'JIT':>3} {'runs/s':>12} {'avg us':>10} {'cores':>10} {'host %':>9}"
    )
    for row in value['programs']:
        numbers = (
            (
                f"{row['runs_per_s']:12.1f} "
                + (
                    f"{row['average_ns']/1000:10.3f}"
                    if row['average_ns'] is not None
                    else f"{'n/a':>10}"
                )
                + f" {row['cpu_cores']:10.4f} {row['host_cpu_pct']:9.4f}"
            )
            if row['stats_available']
            else 'n/a'
        )
        print(
            f"{row['backend']:<20} {row['name']:<16} "
            f"{('n/a' if row['jited'] is None else 'yes' if row['jited'] else 'no'):>3} {numbers}"
        )
        if row['hook']:
            print(f"  {row['hook']}")
    for note in value['notes'] + value['warnings']:
        print(f'\n{note}')


def collect(args):
    processes = discover(args.pid)
    progs = programs(processes)
    notes = [
        'CPU host % uses whole-host capacity; compare it with the on/off difference in percentage points.',
        'Process CPU and BPF runtime can overlap; do not add the two totals.',
        'BPF runtime includes the program and synchronous helpers. It does not measure all probe dispatch, return-probe, scheduling or cache costs.',
        'This window ranks costs within the running configuration; it is not a replacement for the long on/off comparison.',
    ]
    stats_fd = None
    try:
        try:
            # BPF_ENABLE_STATS / BPF_STATS_RUN_TIME; releasing the fd drops only our reference.
            stats_fd = bpf(32, struct.pack('=I', 0))
            notes.append(
                'BPF runtime statistics were temporarily enabled (kernel-wide) and add timing overhead to BPF executions during this window.'
            )
        except OSError as exc:
            notes.append(
                f'Cannot enable BPF runtime statistics: {exc}. Process CPU is still measured; no sysctl was changed.'
            )
        print(
            f'Measuring {len(processes)} processes and {len(progs)} BPF programs for {args.duration:g}s.',
            file=sys.stderr,
            flush=True,
        )
        cpu0 = time.process_time_ns()
        before = snapshot(processes, progs)
        after = before
        end_reason = None
        deadline = time.monotonic() + args.duration
        progress = time.monotonic() + 10
        try:
            while time.monotonic() < deadline:
                time.sleep(min(1, max(0, deadline - time.monotonic())))
                # Retain only whole snapshots. A disappearing PID/fd must not turn
                # into a zero counter or discard all earlier valid measurements.
                try:
                    after = snapshot(processes, progs)
                except (OSError, ObservationChanged) as exc:
                    end_reason = str(exc)
                    break
                if time.monotonic() >= progress and time.monotonic() < deadline:
                    print(
                        f'{max(0, deadline-time.monotonic()):.0f}s remaining',
                        file=sys.stderr,
                        flush=True,
                    )
                    progress = time.monotonic() + 10
        except KeyboardInterrupt:
            end_reason = 'Diagnostic interrupted by signal'
        diagnostic_cpu_s = (time.process_time_ns() - cpu0) / 1e9
    finally:
        if stats_fd is not None:
            os.close(stats_fd)
    valid = after['start_ns'] > before['start_ns'] and sum(after['cpu']) > sum(
        before['cpu']
    )
    value = (
        analyze(before, after, processes, progs, stats_fd is not None) if valid else {}
    )
    value.update(
        version=2,
        status=(
            'error' if not valid else 'complete' if end_reason is None else 'partial'
        ),
        measurement_valid=valid,
        requested_duration_s=args.duration,
        end_reason=(
            end_reason if valid or end_reason else 'No complete sampling interval'
        ),
        notes=notes,
        diagnostic_cpu_s=diagnostic_cpu_s,
        raw_before=before,
        raw_after=after,
    )
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        '--duration', type=float, default=60, help='seconds (default: 60)'
    )
    parser.add_argument(
        '--pid',
        type=int,
        nargs='+',
        help='native observer PID(s); default: discover all running observers',
    )
    parser.add_argument(
        '--output',
        type=Path,
        help='output JSON; default: cpu-diagnosis-TIMESTAMP-PID.json',
    )
    args = parser.parse_args()
    if not 1 <= args.duration <= 3600:
        parser.error('--duration must be 1..3600 seconds')
    if platform.system() != 'Linux':
        parser.error('Run this script on the Linux host running the observer')
    output = args.output or Path(
        time.strftime(
            'cpu-diagnosis-%Y%m%d-%H%M%S', time.gmtime(time.time() + 8 * 3600)
        )
        + f'-{os.getpid()}.json'
    )
    output = output.resolve()
    try:
        value = collect(args)
    except (OSError, RuntimeError, KeyboardInterrupt) as exc:
        value = dict(
            version=2,
            status='error',
            measurement_valid=False,
            requested_duration_s=args.duration,
            end_reason=str(exc) or 'Diagnostic interrupted before sampling started',
        )
    output.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8'
    )
    report(value)
    print(f'\nJSON: {output}')
    return 0 if value['status'] == 'complete' and value['measurement_valid'] else 1


def stop(*_):
    raise KeyboardInterrupt


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, stop)
    try:
        sys.exit(main())
    except (OSError, RuntimeError) as exc:
        sys.exit(f'diagnose: {exc}')
