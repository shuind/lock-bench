#!/usr/bin/env python3
"""Prepare an isolated, runnable copy of the historical diagnostic experiment."""

import argparse
import hashlib
import json
from pathlib import Path
import platform
import shutil
import subprocess
import sys


HERE = Path(__file__).resolve().parent


def replace_once(path, old, new):
    text = path.read_text(encoding='utf-8')
    if text.count(old) != 1:
        raise RuntimeError(f'Expected exactly one matching fragment in {path.name}')
    path.write_text(text.replace(old, new, 1), encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workdir', required=True, type=Path,
                        help='New empty directory for generated files and results')
    parser.add_argument('--kernel-src', type=Path,
                        help='Optional complete Linux source tree; copied into workdir for Kbuild cases')
    parser.add_argument('--kernel-arch', choices=('arm64', 'x86'),
                        help='UAPI header architecture (default: host architecture)')
    args = parser.parse_args()
    if sys.platform != 'linux':
        parser.error('A Linux host with kernel BTF and eBPF support is required')
    arch = {'x86_64': 'x86', 'aarch64': 'arm64'}.get(platform.machine())
    if not arch:
        parser.error('Unsupported architecture: ' + platform.machine())
    for name in ('clang', 'gcc', 'bpftool'):
        if not shutil.which(name):
            parser.error(f'Missing {name}; install the compiler and BPF development tools')
    if not Path('/sys/kernel/btf/vmlinux').is_file():
        parser.error('This kernel does not expose /sys/kernel/btf/vmlinux')

    dest = args.workdir.expanduser().resolve()
    if dest == HERE or HERE.is_relative_to(dest) or dest.is_relative_to(HERE):
        parser.error('Use a workdir outside the source checkout')
    if dest.exists() and (not dest.is_dir() or any(dest.iterdir())):
        parser.error('The workdir must be new or empty')
    kernel = args.kernel_src.expanduser().resolve() if args.kernel_src else None
    if kernel and (not (kernel / 'Makefile').is_file() or dest.is_relative_to(kernel)):
        parser.error('Provide a complete Linux source tree outside the workdir')
    kernel_arch = args.kernel_arch or arch
    if args.kernel_arch and not kernel:
        parser.error('--kernel-arch requires --kernel-src')
    if kernel and not (kernel / 'arch' / kernel_arch / 'Makefile').is_file():
        parser.error(f'The source tree does not contain arch/{kernel_arch}/Makefile')
    dest.mkdir(parents=True, exist_ok=True)
    for name in ('source', 'instrumented', 'http'):
        shutil.copytree(HERE / name, dest / name)
    for name in ('run.py', 'run.sh', 'http_measure.py', 'kbuild_measure.py',
                 'program_stats.py', 'diagnostic_observer.py', 'controlled.c', 'gate_exec.c'):
        shutil.copy2(HERE / name, dest / name)

    if kernel:
        print('Copying the Linux source tree to the private workdir...', flush=True)
        shutil.copytree(kernel, dest / 'kernel', symlinks=True,
                        ignore=shutil.ignore_patterns('.git'))
        kernel_copy = (dest / 'kernel').resolve()
        for path in kernel_copy.rglob('*'):
            if path.is_symlink() and not path.resolve().is_relative_to(kernel_copy):
                raise RuntimeError(f'Kernel source contains an external symlink: {path}')
        # The archived runner was for ARM64. Other architectures need the
        # matching UAPI headers; counts can differ from the original machine.
        replace_once(dest / 'kbuild_measure.py', "'ARCH=arm64'", repr('ARCH=' + kernel_arch))

    # Keep runtime statistics local to this run if the sysctl is off. Holding
    # the stats FD enables them while open; this does not change the sysctl.
    replace_once(dest / 'run.py',
        "        if not args.local_smoke or os.uname().machine=='aarch64':parser.error('Existing bpf_stats_enabled must be 1; no setting changed')\n",
        '')
    replace_once(dest / 'run.py',
        "        plan=[c for c in plan if c['name']in args.only]\n    rounds=1 if args.local_smoke else args.rounds",
        "        plan=[c for c in plan if c['name']in args.only]\n"
        "    if any(c['workload']=='kbuild' for c in plan) and not (HERE/'kernel/Makefile').is_file():\n"
        "        parser.error('Kbuild requires a workdir prepared with --kernel-src')\n"
        "    rounds=1 if args.local_smoke else args.rounds")

    # The four fixture files are regenerated locally. The server computes and
    # checks SHA-256 as part of each request, as in the historical workload.
    fixtures = dest / 'fixtures'
    fixtures.mkdir()
    files = []
    block = bytes(range(256)) * 4096  # 1 MiB
    for index in range(4):
        data = block[index:] + block[:index]
        path = fixtures / f'input-{index}.bin'
        with path.open('wb') as stream:
            for _ in range(4):
                stream.write(data)
        digest = hashlib.sha256()
        with path.open('rb') as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                digest.update(chunk)
        files.append(dict(id=index, name=path.name, bytes=path.stat().st_size,
                          sha256=digest.hexdigest()))
    (fixtures / 'manifest.json').write_text(json.dumps(dict(files=files,
        file_bytes=4194304, file_count=4, response_bytes=65), indent=2) + '\n', encoding='utf-8')

    sys.path.insert(0, str(dest / 'source'))
    from observer.build import build
    from observer.catalog import backends
    selected = backends()
    build([selected['mmap/fentry'], selected['mmap/tracepoint']])
    for method in ('fentry', 'tracepoint'):
        source = dest / 'instrumented' / 'observer' / 'mmap' / method / 'probe.bpf.c'
        for total in (False, True):
            label = 'total' if total else 'segments'
            subprocess.run(['clang', '-O2', '-g', '-target', 'bpf',
                '-D__TARGET_ARCH_' + arch, '-DDIAG_TOTAL_ONLY=' + str(int(total)),
                '-I' + str(dest / 'source/observer/.build'),
                '-I' + str(dest / 'source/observer/common'), '-c', str(source),
                '-o', str(dest / f'{method}-{label}.bpf.o')], check=True)
    subprocess.run(['gcc', '-O2', '-g', '-Wall', '-Wextra', '-Werror',
        '-Wno-deprecated-declarations', '-pthread', str(dest / 'controlled.c'),
        '-o', str(dest / 'controlled'), '-lcrypto'], check=True)
    subprocess.run(['gcc', '-O2', '-Wall', '-Wextra', '-Werror',
        str(dest / 'gate_exec.c'), '-o', str(dest / 'gate-exec')], check=True)
    print('Prepared:', dest)
    print('Try: sudo python3', dest / 'run.py', '--local-smoke --only fentry-http-32 tracepoint-http-32')
    if not kernel:
        print('Kbuild cases require --kernel-src when preparing a new workdir.')


if __name__ == '__main__':
    main()
