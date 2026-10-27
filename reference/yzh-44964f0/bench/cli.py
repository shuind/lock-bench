import argparse
import json
import math
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from workload.registry import ROOT, WORKLOADS, NATIVE, build, resolve
from observer.cli import (
    observation,
    build_arguments,
    observer_build,
    add_commands,
)
from cli import positive, integer, execute
from system.cli import arguments as system_arguments


def nonnegative(value):
    number = int(value)
    if number < 0:
        raise argparse.ArgumentTypeError('Expected a nonnegative integer')
    return number


def quota(value):
    number = float(value)
    if not math.isfinite(number) or number < 0:
        raise argparse.ArgumentTypeError('Expected a finite nonnegative CPU quota')
    return number


def validate_observation(args):
    from observer.catalog import resolve

    return resolve(args)


def load_arguments(parser):
    parser.add_argument('--workload', choices=WORKLOADS, required=True)
    parser.add_argument(
        '--duration', type=positive, help='Active seconds for time-limited workloads; default 30'
    )
    parser.add_argument(
        '--operations',
        type=nonnegative,
        help='Fixed operations; overrides duration; memory-pressure uses passes',
    )
    parser.add_argument(
        '--concurrency', type=integer, help='Worker/client count; workload-specific default'
    )
    parser.add_argument('--file-mib', type=integer, help='File data size in MiB')
    parser.add_argument('--anon-mib', type=integer, help='Anonymous data target in MiB')
    parser.add_argument('--file-threads', type=integer, help='file-anon-pressure file workers')
    parser.add_argument(
        '--memory-threads', type=integer, help='file-anon-pressure anonymous workers'
    )
    parser.add_argument(
        '--memory-limit-mib',
        type=nonnegative,
        help='Memory+swap cap in MiB; swap disabled; 0=no cap',
    )
    parser.add_argument('--cpu-limit', type=quota, help='CPU quota in cores; 0=no quota')
    parser.add_argument('--project', type=Path, help='Local source directory for zlib/actrail')
    parser.add_argument(
        '--run-timeout',
        type=positive,
        default=600,
        help='Preparation/active-stage watchdog seconds',
    )


def workload_build(args):
    names = list(WORKLOADS) if args.workload == 'all' else [args.workload]
    compiled_native = False
    for name in names:
        if name in NATIVE and compiled_native:
            continue
        build(name)
        compiled_native |= name in NATIVE
    return 0


def bench_build(args):
    code = observer_build(args)
    return code or workload_build(args)


def workload_run(args):
    from workload.drivers import run
    from .resources import enter_workload, Resources, own_directory

    resolve(args)
    if args.cpu_limit < 0 or args.concurrency > 1024:
        raise ValueError('Invalid resource or concurrency value')
    if 'LOCKBENCH_WORKLOAD_FD' in os.environ:
        enter_workload()
        return run(args)
    # Standalone workload uses the same private resource boundary, without an observer.
    if sys.platform != 'linux':
        raise RuntimeError('Workloads require Linux')
    folder = args.workdir or Path(tempfile.mkdtemp(prefix='lockbench-workload-'))
    folder.mkdir(parents=True, exist_ok=True)
    own_directory(folder)
    args.workdir = folder
    resources = Resources(args).create()
    try:
        from .runner import flags, WORK_FLAGS

        env = dict(os.environ, **resources.environment(), LOCKBENCH_STANDALONE_CHILD='1')
        command = [
            sys.executable,
            str(ROOT / 'lockbench.py'),
            'workload',
            'run',
            '--workload',
            args.workload,
            '--workdir',
            str(folder),
            *flags(args, WORK_FLAGS),
        ]
        # Pass the requested resource values; defaults must not re-enable a cap.
        command += ['--memory-limit-mib', '0', '--cpu-limit', '0']
        return subprocess.call(command, cwd=ROOT, env=env)
    finally:
        resources.close()


def workload_dispatch(args):
    if 'LOCKBENCH_STANDALONE_CHILD' in os.environ:
        from .resources import enter_workload
        from workload.drivers import run

        resolve(args)
        enter_workload()
        return run(args)
    return workload_run(args)


def bench_run(args):
    from .runner import run
    from observer.api import factory

    create_observer = factory(args, duration=args.run_timeout + 5)
    from system.api import factory as system_factory

    create_system = (
        system_factory(args.system_interval_ms, filename='system.jsonl')
        if args.system == 'on'
        else None
    )
    if args.cpu_limit is not None and args.cpu_limit < 0:
        raise ValueError('--cpu-limit cannot be negative')
    if args.concurrency is not None and args.concurrency > 1024:
        raise ValueError('--concurrency must be <=1024')
    return run(args, create_observer, create_system)


def bench_analyze(args):
    from .analysis import analyze

    summary = analyze(args.input)
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


def bench_report(args):
    from .report import report

    return report(args.input, args.output)


def bench_check(args):
    if args.input:
        from .analysis import analyze

        expected = json.loads((args.input / 'summary.json').read_text(encoding='utf-8'))
        if analyze(args.input, write=False) != expected:
            raise ValueError('Summary differs from raw measurements')
        print('PASS: unified raw data and statistics agree')
    else:
        from .checks.verify_results import verify_report

        verify_report(ROOT / 'docs/REPORT.html')
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog='lockbench', description='Host-wide eBPF lock observation and development experiments'
    )
    groups = parser.add_subparsers(dest='component', required=True)
    add_commands(groups.add_parser('observer', help='Build or run the host-wide BPF observer'))
    loads = groups.add_parser(
        'workload', help='Build and run workloads without BPF'
    ).add_subparsers(dest='action', required=True)
    p = loads.add_parser('list')
    p.set_defaults(
        handler=lambda args: print('\n'.join(f'{k:22} {v}' for k, v in WORKLOADS.items())) or 0
    )
    p = loads.add_parser('build')
    p.add_argument('--workload', choices=(*WORKLOADS, 'all'), default='all')
    p.set_defaults(handler=workload_build)
    p = loads.add_parser('run')
    load_arguments(p)
    p.add_argument('--workdir', type=Path)
    p.set_defaults(handler=workload_dispatch)
    experiments = groups.add_parser(
        'bench', help='Run experiments, analyze data and update HTML'
    ).add_subparsers(dest='action', required=True)
    p = experiments.add_parser('build')
    build_arguments(p)
    p.add_argument('--workload', choices=(*WORKLOADS, 'all'), default='all')
    p.set_defaults(handler=bench_build)
    p = experiments.add_parser('run')
    load_arguments(p)
    observation(p, 'on')
    system_arguments(p, toggle=True, output=False)
    p.add_argument('--repeats', type=integer, default=7)
    p.add_argument('--seed', type=int, default=20261016)
    p.add_argument('--output', type=Path)
    p.set_defaults(handler=bench_run)
    p = experiments.add_parser('analyze')
    p.add_argument('--input', type=Path, required=True)
    p.set_defaults(handler=bench_analyze)
    p = experiments.add_parser('report')
    p.add_argument('--input', type=Path, nargs='*')
    p.add_argument('--output', type=Path, default=ROOT / 'docs/REPORT.html')
    p.set_defaults(handler=bench_report)
    p = experiments.add_parser('check')
    p.add_argument('--input', type=Path)
    p.set_defaults(handler=bench_check)
    return execute(parser, argv)
