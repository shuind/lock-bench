"""Host metrics commands; no lock collector dependency."""

import argparse
import json
from pathlib import Path
import sys
import tempfile

from cli import execute, integer, observation_duration
from session import run as run_session
from .api import factory


def interval(value):
    number = integer(value)
    if not 100 <= number <= 60000:
        raise argparse.ArgumentTypeError('Expected a system interval of 100..60000 ms')
    return number


def arguments(parser, toggle=False, output=True):
    if toggle:
        parser.add_argument(
            '--system', choices=('on', 'off'), default='on', help='Host metrics; default on'
        )
    parser.add_argument(
        '--system-interval-ms',
        type=interval,
        default=1000,
        help='Host sample interval, 100..60000 ms',
    )
    if output:
        parser.add_argument('--system-output', type=Path, help='Write every host sample as JSONL')


def run(args):
    if sys.platform != 'linux':
        raise RuntimeError('Host metrics require Linux')
    with tempfile.TemporaryDirectory(prefix='lockbench-system-') as name:
        collector = factory(args.system_interval_ms, args.system_output, live=True)(Path(name))
        result = run_session({'system': collector}, args.duration)
        value = result['collectors']['system']
        value['stop_reason'] = result['stop_reason']
        print(json.dumps(value, ensure_ascii=False), flush=True)
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(prog='lockbench system', description='Host system metrics')
    actions = parser.add_subparsers(dest='action', required=True)
    item = actions.add_parser('run', help='Sample CPU, memory, load and PSI')
    arguments(item)
    observation_duration(item)
    item.set_defaults(handler=run)
    return execute(parser, argv)


if __name__ == '__main__':
    raise SystemExit(main())
