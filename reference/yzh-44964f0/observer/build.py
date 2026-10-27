"""Compile each product from its own probe source and linked descriptor."""

import argparse
import os
import platform
from pathlib import Path
import shutil
import subprocess
import sys

from .catalog import ROOT, select_products


def compiler(variable, candidates):
    configured = os.environ.get(variable)
    for name in (configured,) if configured else candidates:
        executable = shutil.which(name)
        if executable:
            return executable
    if configured:
        raise ValueError(f'{variable} compiler not found: {configured}')
    raise ValueError(
        f'No compiler found ({", ".join(candidates)}); '
        f'install one or set {variable} to its executable path'
    )


def prepare_header(folder, vmlinux_header=None, btf_path=Path('/sys/kernel/btf/vmlinux'), cc=None):
    """Use an explicit header, or export BTF with the already required libbpf."""
    temporary = folder / 'vmlinux.h.tmp'
    try:
        if vmlinux_header is not None:
            data = Path(vmlinux_header).read_bytes()
            if not data.strip():
                raise ValueError('--vmlinux-header must name a nonempty C header')
            temporary.write_bytes(data)
        else:
            if not btf_path.is_file():
                raise ValueError(
                    f'Kernel BTF not found: {btf_path}; use --vmlinux-header with a compatible header. '
                    'Running observers still requires kernel BTF.'
                )
            helper = folder / 'btf-header'
            subprocess.run(
                [
                    cc or compiler('CC', ('gcc', 'cc', 'clang')),
                    '-O2',
                    '-Wall',
                    '-Wextra',
                    '-Werror',
                    str(ROOT / 'build_btf.c'),
                    '-o',
                    str(helper),
                    '-lbpf',
                    '-lelf',
                    '-lz',
                ],
                check=True,
            )
            with temporary.open('wb') as stream:
                subprocess.run([str(helper), str(btf_path)], stdout=stream, check=True)
        temporary.replace(folder / 'vmlinux.h')
    finally:
        temporary.unlink(missing_ok=True)


def build(products, vmlinux_header=None):
    if sys.platform != 'linux':
        raise RuntimeError('Observer builds require Linux')
    arch = {'aarch64': 'arm64', 'x86_64': 'x86'}.get(platform.machine())
    if not arch:
        raise RuntimeError('Unsupported architecture: ' + platform.machine())
    cc = compiler('CC', ('gcc', 'cc', 'clang'))
    clang = compiler('CLANG', ('clang',))
    folder = ROOT / '.build'
    folder.mkdir(exist_ok=True)
    prepare_header(folder, vmlinux_header, cc=cc)
    for item in products:
        output = item.directory / 'dist'
        output.mkdir(exist_ok=True)
        binary = output / 'observer.tmp'
        variants = [(item.directory / 'probe.bpf.c', item.object)]
        if item.timer:
            variants.append((item.directory / 'probe.timer.bpf.c', item.timer_object))
        staged = []
        for source, destination in variants:
            temporary = destination.with_name(destination.name + '.tmp')
            subprocess.run(
                [
                    clang,
                    '-g',
                    '-O2',
                    '-target',
                    'bpf',
                    '-D__TARGET_ARCH_' + arch,
                    '-I' + str(folder),
                    '-I' + str(ROOT / 'common'),
                    '-c',
                    str(source),
                    '-o',
                    str(temporary),
                ],
                check=True,
            )
            staged.append((temporary, destination))
        subprocess.run(
            [
                cc,
                '-O2',
                '-g',
                '-Wall',
                '-Wextra',
                '-Werror',
                '-Wno-unused-parameter',
                '-Wno-misleading-indentation',
                '-I' + str(ROOT / 'common'),
                str(ROOT / 'common/runtime.c'),
                str(item.directory / 'backend.c'),
                '-o',
                str(binary),
                '-lbpf',
                '-lelf',
                '-lz',
            ],
            check=True,
        )
        for temporary, destination in staged:
            temporary.replace(destination)
        binary.replace(item.binary)
        print('Built ' + item.id, flush=True)
    return 0


def main():
    from .cli import build_arguments

    parser = argparse.ArgumentParser(description=__doc__)
    build_arguments(parser)
    args = parser.parse_args()
    return build(
        select_products(args.target, args.scheme, args.mmap_scheme, args.cgroup_scheme),
        args.vmlinux_header,
    )


if __name__ == '__main__':
    sys.exit(main())
