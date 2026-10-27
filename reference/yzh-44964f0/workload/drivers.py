"""Pure workload preparation and execution; no observer or experiment imports."""

import json
import os
from pathlib import Path
import select
import shutil
import socket
import struct
import subprocess
import sys
import time

from .registry import ROOT, NATIVE
from .runtime import Session


def line(process, timeout=300):
    if not select.select([process.stdout], [], [], timeout)[0]:
        raise TimeoutError('Workload readiness/result timed out')
    value = process.stdout.readline()
    if not value:
        raise RuntimeError(f'Workload exited {process.poll()}; see workload.log')
    return json.loads(value)


def native(session):
    args = session.args
    binary = ROOT / 'workload/native/.build/ops'
    if not binary.exists():
        raise RuntimeError('Build the workload first: workload build --workload ' + args.workload)
    with (args.workdir / 'workload.log').open('w') as log:
        p = session.watch(
            subprocess.Popen(
                [
                    str(binary),
                    args.workload,
                    str(args.operations),
                    str(args.duration),
                    str(args.concurrency),
                    str(args.anon_mib * 1024**2),
                ],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=log,
                text=True,
            )
        )
        line(p)
        session.ready(worker_pid=p.pid, concurrency=args.concurrency)
        p.stdin.write('G')
        p.stdin.flush()
        value = line(p, args.run_timeout)
        if value['error'] or not value['operations']:
            raise RuntimeError('Native workload failed: ' + repr(value))
        session.result(value.pop('operations'), **value)
        p.stdin.write('F')
        p.stdin.flush()
        if p.wait(timeout=5):
            raise RuntimeError('Native workload cleanup failed')


def memory_pressure(session):
    args = session.args
    folder = ROOT / 'workload/memory-pressure'
    binary = folder / '.build/memory_scan'
    if not binary.exists():
        raise RuntimeError('Build memory-pressure first')
    file = args.workdir / 'pages.dat'
    page = bytearray(4096)
    with file.open('wb') as stream:
        for i in range(args.file_mib * 256):
            struct.pack_into('=Q', page, 0, i)
            stream.write(page)
    try:
        with (args.workdir / 'workload.log').open('w') as log:
            p = session.watch(
                subprocess.Popen(
                    [
                        str(binary),
                        str(file),
                        str(args.operations or 15),
                        str(args.anon_mib),
                        str(args.concurrency),
                    ],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=log,
                    text=True,
                )
            )
            prepared = line(p, args.run_timeout)
            session.ready(**prepared)
            p.stdin.write('G')
            p.stdin.flush()
            value = line(p, args.run_timeout)
            if not value['verified']:
                raise RuntimeError('Page checksum mismatch')
            session.result(value['page_visits'], unit='page-visits', **value)
            p.stdin.write('F')
            p.stdin.flush()
            if p.wait(timeout=10):
                raise RuntimeError('Page scanner failed')
    finally:
        file.unlink(missing_ok=True)


def file_anon_pressure(session):
    import importlib.util

    args = session.args
    folder = ROOT / 'workload/file-anon-pressure'
    binary = folder / '.build/workload'
    if not binary.exists():
        raise RuntimeError('Build file-anon-pressure first')
    spec = importlib.util.spec_from_file_location('file_anon_pressure_metrics', folder / 'metrics.py')
    metrics = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(metrics)
    files = args.workdir / 'files'
    files.mkdir()
    parent, child = socket.socketpair()
    env = dict(
        os.environ,
        BENCH_PROGRESS=str(args.workdir / 'progress.bin'),
        BENCH_PHASE_FD=str(child.fileno()),
    )
    env.pop('BENCH_VALIDATE_READ', None)

    def receive(word, timeout):
        if not select.select([parent], [], [], timeout)[0] or parent.recv(1) != word:
            raise RuntimeError('Native pressure workload handshake failed')

    try:
        with (args.workdir / 'workload.log').open('w') as log:
            p = session.watch(
                subprocess.Popen(
                    [
                        str(binary),
                        str(args.memory_threads),
                        str(args.file_threads),
                        str(args.anon_mib * 1024**2),
                        str(args.file_mib * 1024**2),
                        str(files),
                        '30000',
                    ],
                    env=env,
                    pass_fds=(child.fileno(),),
                    stdout=log,
                    stderr=log,
                )
            )
            child.close()
            receive(b'R', args.run_timeout)
            progress = metrics.decode((args.workdir / 'progress.bin').read_bytes())
            if progress['ready'] != args.file_threads + args.memory_threads:
                raise RuntimeError('Workers not ready')
            session.ready(worker_pid=p.pid, workers=progress['workers'])
            parent.sendall(b'G')
            time.sleep(args.duration)
            parent.sendall(b'D')
            receive(b'S', 15)
            progress = metrics.decode((args.workdir / 'progress.bin').read_bytes())
            rates = metrics.rates(progress)
            if not progress['file_read_bytes'] or not progress['memory_node_visits']:
                raise RuntimeError('Pressure workload completed no useful work')
            session.result(
                progress['file_read_bytes'], unit='logical-bytes', progress=progress, **rates
            )
    finally:
        if 'p' in locals() and p.poll() is None:
            p.kill()
            p.wait(timeout=10)
        parent.close()
        child.close()
        for file in files.glob('tmpfile.*'):
            file.unlink()
        files.rmdir()


def compile_project(session):
    args = session.args
    project = args.project.resolve()
    if not project.is_dir():
        raise ValueError('--project is not a directory')
    required = 'configure' if args.workload == 'zlib' else 'Cargo.toml'
    if not (project / required).is_file():
        raise ValueError('--project must contain ' + required)
    if args.workdir.resolve().is_relative_to(project):
        raise ValueError('Work directory must be outside source project')
    source = args.workdir / 'source'
    shutil.copytree(
        project,
        source,
        ignore=shutil.ignore_patterns(
            '.git', 'target', 'node_modules', '__pycache__', 'results', '.build'
        ),
    )
    env = dict(os.environ)
    with (args.workdir / 'build.log').open('w') as log:
        if args.workload == 'zlib':
            if not (source / 'configure').exists():
                raise ValueError('--project must be zlib source')
            subprocess.run(
                ['make', 'distclean'], cwd=source, env=env, stdout=log, stderr=log, check=False
            )
            subprocess.run(
                ['bash', 'configure', '--static'],
                cwd=source,
                env=env,
                stdout=log,
                stderr=log,
                check=True,
                timeout=args.run_timeout,
            )
            command = ['make', '-j', str(args.concurrency)]
        else:
            if not (source / 'Cargo.toml').exists():
                raise ValueError('--project must be AcTrail source')
            cargo = shutil.which('cargo') or str(Path.home() / '.cargo/bin/cargo')
            env['CARGO_TARGET_DIR'] = str(args.workdir / 'target')
            env.pop('ACTRAIL_SKIP_JAVA_AGENT_BUILD', None)
            env.pop('ACTRAIL_JAVA_AGENT_PREBUILT_JAR', None)
            env['ACTRAIL_REQUIRE_JAVA_AGENT_BUILD'] = '1'
            command = [
                cargo,
                'build',
                '--offline',
                '--package',
                'ctl',
                '--jobs',
                str(args.concurrency),
            ]
        session.ready(project=str(project), build_directory=str(source))
        subprocess.run(
            command,
            cwd=source,
            env=env,
            stdout=log,
            stderr=log,
            check=True,
            timeout=args.run_timeout,
        )
        artifact = (
            source / 'libz.a' if args.workload == 'zlib' else args.workdir / 'target/debug/ctl'
        )
        if not artifact.is_file():
            raise RuntimeError('Build artifact missing: ' + str(artifact))
        session.result(
            1, unit='clean-builds', artifact=str(artifact), artifact_bytes=artifact.stat().st_size
        )


def run(args):
    if sys.platform != 'linux':
        raise RuntimeError('Workloads require Linux')
    args.workdir.mkdir(parents=True, exist_ok=True)
    copies = 4 if args.workload == 'http-file' else 1
    if args.workload in ('http-file', 'memory-pressure', 'file-anon-pressure'):
        required = args.file_mib * 1024**2 * copies + 64 * 1024**2
        if shutil.disk_usage(args.workdir).free < required:
            raise RuntimeError('Not enough free disk for private workload files')
    session = Session(args)
    try:
        if args.workload in NATIVE:
            native(session)
        elif args.workload == 'memory-pressure':
            memory_pressure(session)
        elif args.workload == 'file-anon-pressure':
            file_anon_pressure(session)
        elif args.workload in ('zlib', 'actrail'):
            compile_project(session)
        else:
            from .http_service import execute

            execute(session)
    finally:
        session.close()
    return 0
