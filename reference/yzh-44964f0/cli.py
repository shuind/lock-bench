"""Shared CLI value parsing and execution, independent of collectors."""

import argparse
from pathlib import Path
import subprocess
from logutil import log_line


def positive(value):
    number = float(value)
    if not 0 < number <= 86400:
        raise argparse.ArgumentTypeError('Expected a positive number <= 86400')
    return number


def integer(value):
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError('Expected a positive integer')
    return number


def observation_duration(parser):
    parser.add_argument(
        '--duration',
        type=positive,
        help='Stop after this many seconds; omit to run until Ctrl+C (maximum 86400)',
    )


def execute(parser, argv):
    args = parser.parse_args(argv)
    for key, value in vars(args).items():
        if isinstance(value, Path):
            setattr(args, key, value.resolve())
        elif isinstance(value, list) and value and isinstance(value[0], Path):
            setattr(args, key, [path.resolve() for path in value])
    try:
        return args.handler(args)
    except KeyboardInterrupt:
        return 130
    except (ValueError, RuntimeError, OSError, subprocess.SubprocessError) as exc:
        log_line(f'lockbench: {exc}')
        return 1
