#!/usr/bin/env python3
"""CLI composition root for independent collectors and development commands."""
import argparse
import json
from pathlib import Path
import sys
import tempfile

from cli import execute, observation_duration


def combined_run(args):
    from observer.api import factory as locks
    from system.api import factory as system
    from session import run

    if sys.platform != 'linux':
        raise RuntimeError('Observation sessions require Linux')
    with tempfile.TemporaryDirectory(prefix='lockbench-session-') as name:
        directory = Path(name)
        collectors = {
            'locks': locks(
                args, live=True, duration=args.duration + 5 if args.duration is not None else None
            )(directory / 'locks')
        }
        if args.system == 'on':
            collectors['system'] = system(args.system_interval_ms, args.system_output, live=True)(
                directory / 'system'
            )
        print(json.dumps(run(collectors, args.duration), ensure_ascii=False), flush=True)
    return 0


def combined(argv):
    from observer.cli import observation
    from system.cli import arguments

    parser = argparse.ArgumentParser(
        prog='lockbench run', description='Run independent collectors in one session'
    )
    observation(parser)
    arguments(parser, toggle=True)
    observation_duration(parser)
    parser.set_defaults(handler=combined_run)
    return execute(parser, argv)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    root = Path(__file__).resolve().parent
    locks = (root / 'observer/cli.py').is_file()
    host = (root / 'system/cli.py').is_file()
    analysis = (root / 'analysis/cli.py').is_file()
    if analysis and argv and argv[0] == 'compare':
        from analysis.cli import main as compare

        return compare(argv[1:])
    if locks and argv and argv[0] == 'observer':
        from observer.cli import main as observe

        return observe(argv[1:])

    if host and argv and argv[0] == 'system':
        from system.cli import main as system

        return system(argv[1:])

    if locks and host and argv and argv[0] == 'run':
        return combined(argv[1:])
    development = (
        locks
        and host
        and (root / 'bench/cli.py').is_file()
        and (root / 'workload/registry.py').is_file()
    )
    if development and argv and argv[0] in ('workload', 'bench'):
        from bench.cli import main as experiment

        return experiment(argv)

    parser = argparse.ArgumentParser(
        prog='lockbench', description='Independent host collectors and observation sessions'
    )
    groups = parser.add_subparsers(dest='component', required=True)
    if locks:
        groups.add_parser('observer', help='Build or run the host-wide BPF observer')
    if host:
        groups.add_parser('system', help='Run the independent system metrics collector')
    if locks and host:
        groups.add_parser('run', help='Combine lock and system collectors in a session')
    if analysis:
        groups.add_parser('compare', help='Compare exported on/off sessions offline')
    if development:
        groups.add_parser('workload', help='Run development workloads')
        groups.add_parser('bench', help='Run and analyze development experiments')
    parser.parse_args(argv)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
