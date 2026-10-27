"""Comparison commands independent of collectors and experimental workloads."""

import argparse
from pathlib import Path

from cli import execute


def compare(args):
    from .compare import write_report

    write_report(args.on, args.off, args.output, args.on_system, args.off_system)
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog='lockbench compare', description='Compare on/off sessions offline'
    )
    parser.add_argument('--on', type=Path, required=True, help='Completed observation-on JSON')
    parser.add_argument('--off', type=Path, required=True, help='Completed observation-off JSON')
    parser.add_argument(
        '--on-system', type=Path, help='Full system JSONL for observation-on session'
    )
    parser.add_argument(
        '--off-system', type=Path, help='Full system JSONL for observation-off session'
    )
    parser.add_argument(
        '--output',
        type=Path,
        default=Path('comparison.html'),
        help='Standalone HTML; default comparison.html',
    )
    parser.set_defaults(handler=compare)
    return execute(parser, argv)
