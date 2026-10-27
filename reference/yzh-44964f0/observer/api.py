"""Composition root: public options select products, orchestration sees a contract."""

from dataclasses import replace
import json
import subprocess
import sys
import tempfile

from .catalog import resolve, select_products
from session import CollectorFactory, run as run_session
from .native import NativeObserver, CompositeObserver


def factory(args, live=False, duration=None) -> CollectorFactory:
    selections = resolve(args)
    if duration is not None:
        selections = [replace(item, duration=min(duration, 86400)) for item in selections]

    def create(directory):
        children = [
            NativeObserver(item, directory / item.backend.target, live=live) for item in selections
        ]
        return children[0] if len(children) == 1 else CompositeObserver(children)

    return create


def run(args):
    if sys.platform != 'linux':
        raise RuntimeError('Observers require Linux')
    create = factory(
        args, live=True, duration=args.duration + 5 if args.duration is not None else None
    )
    with tempfile.TemporaryDirectory(prefix='lockbench-observer-') as name:
        from pathlib import Path

        result = run_session({'locks': create(Path(name))}, args.duration)
        value = result['collectors']['locks']
        value['stop_reason'] = result['stop_reason']
        print(json.dumps(value, ensure_ascii=False), flush=True)
    return 0


def inspect(args):
    products = select_products(args.target, args.scheme, args.mmap_scheme, args.cgroup_scheme)
    if args.object and len(products) != 1:
        raise ValueError('--object requires a single backend selection')
    values = {}
    for item in products:
        command = [str(item.binary), 'inspect', '--object', str(args.object or item.object)]
        output = subprocess.check_output(command, text=True)
        values[item.id] = json.loads(output)
    print(
        json.dumps(
            next(iter(values.values())) if len(values) == 1 else values,
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0
