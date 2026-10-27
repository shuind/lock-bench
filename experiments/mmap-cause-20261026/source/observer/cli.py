"""Observer command definitions, independent of development workloads."""

import argparse
from pathlib import Path

from cli import observation_duration, integer, execute


def observation(parser, default='off'):
    parser.add_argument(
        '--target', default='cgroup', help='mmap,cgroup,fork; comma-separated, or all'
    )
    parser.add_argument('--observe', choices=('on', 'off'), default=default)
    parser.add_argument(
        '--scheme',
        choices=('fentry', 'kprobe', 'tracepoint', 'raw', 'contention'),
        help='Default per object: mmap=tracepoint, cgroup=fentry, fork=kprobe',
    )
    parser.add_argument('--collect', choices=('count', 'state', 'stack'), default='stack')
    parser.add_argument(
        '--event-counts', choices=('on', 'off'), default='on',
        help='Normal event counters, fixed at load time; errors always retained',
    )
    parser.add_argument('--timeout', choices=('none', 'poll', 'timer'), default='poll')
    for target, choices in [
        ('mmap', ('fentry', 'kprobe', 'tracepoint', 'raw')),
        ('cgroup', ('fentry', 'kprobe', 'contention')),
    ]:
        parser.add_argument(
            '--' + target + '-scheme',
            choices=choices,
            help='Override --scheme for this object',
        )
    for target in ('mmap', 'cgroup', 'fork'):
        parser.add_argument('--' + target + '-collect', choices=('count', 'state', 'stack'))
        parser.add_argument('--' + target + '-event-counts', choices=('on', 'off'))
        parser.add_argument(
            '--' + target + '-timeout',
            choices=('none', 'poll') if target == 'fork' else ('none', 'poll', 'timer'),
        )
    parser.add_argument('--threshold-ns', type=integer, default=100000000)
    parser.add_argument('--poll-ms', type=integer, default=100)
    parser.add_argument('--rw', choices=('both', 'write'), default='both')
    parser.add_argument('--object', type=Path)


def product_arguments(parser):
    parser.add_argument('--target', default='all', help='mmap,cgroup,fork; comma-separated, or all')
    parser.add_argument(
        '--scheme',
        choices=('fentry', 'kprobe', 'tracepoint', 'raw', 'contention'),
        help='Omit to include every supported method',
    )
    parser.add_argument('--mmap-scheme', choices=('fentry', 'kprobe', 'tracepoint', 'raw'))
    parser.add_argument('--cgroup-scheme', choices=('fentry', 'kprobe', 'contention'))


def build_arguments(parser):
    product_arguments(parser)
    parser.add_argument('--vmlinux-header', type=Path, help='Use an existing compatible vmlinux.h')


def observer_build(args):
    from observer.build import build
    from observer.catalog import select_products

    return build(
        select_products(args.target, args.scheme, args.mmap_scheme, args.cgroup_scheme),
        getattr(args, 'vmlinux_header', None),
    )


def observer_run(args):
    from observer.api import run

    return run(args)


def observer_inspect(args):
    from observer.api import inspect

    return inspect(args)


def add_commands(parser):
    actions = parser.add_subparsers(dest='action', required=True)
    item = actions.add_parser('build', help='Build independent backend executables and .o files')
    build_arguments(item)
    item.set_defaults(handler=observer_build)
    item = actions.add_parser('run', help='Observe existing host activity')
    observation(item)
    observation_duration(item)
    item.set_defaults(handler=observer_run)
    item = actions.add_parser('inspect', help='List programs and maps without loading BPF')
    product_arguments(item)
    item.add_argument('--object', type=Path)
    item.set_defaults(handler=observer_inspect)


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog='lockbench observer', description='Host-wide eBPF lock observation'
    )
    add_commands(parser)
    return execute(parser, argv)


if __name__ == '__main__':
    raise SystemExit(main())
