from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKLOADS = {
    'mmap': 'Repeated mmap + munmap of one page',
    'mprotect': 'Change permissions twice on an existing mapping',
    'read-maps': 'Read /proc/self/maps repeatedly',
    'fault': 'Touch anonymous pages and discard between scans',
    'fork': 'Concurrent fork, exit and wait',
    'cgroup-migrate': 'Move the process between two isolated cgroups',
    'fork-migrate': 'Concurrent fork and cgroup migration',
    'mmap-contention': 'Shared-address-space mprotect writers and maps readers',
    'memory-pressure': 'Scan a fixed file mapping under a memory cap',
    'http': 'Start, request and stop independent HTTP services',
    'http-file': 'Persistent HTTP clients mmap and checksum files per request',
    'zlib': 'Clean zlib build from a local source directory',
    'actrail': 'Clean AcTrail ctl build and dependencies from a local checkout',
    'file-anon-pressure': 'File pages and growing anonymous lists compete for memory',
}
NATIVE = set(list(WORKLOADS)[:8])
DEFAULTS = {
    'memory-pressure': dict(
        file_mib=256, anon_mib=16, concurrency=4, operations=15, memory_limit_mib=64
    ),
    'file-anon-pressure': dict(
        file_mib=4096,
        anon_mib=3072,
        file_threads=1000,
        memory_threads=1000,
        memory_limit_mib=4096,
        cpu_limit=4,
    ),
    'http-file': dict(file_mib=4, concurrency=32),
    'http': dict(concurrency=1, operations=12),
    'fork': dict(concurrency=4),
    'fork-migrate': dict(concurrency=5),
    'mmap-contention': dict(anon_mib=64, concurrency=3),
}


def resolve(args):
    for name, value in dict(
        duration=30.0,
        operations=0,
        concurrency=1,
        file_mib=4,
        anon_mib=16,
        file_threads=4,
        memory_threads=4,
        memory_limit_mib=0,
        cpu_limit=0,
    ).items():
        if getattr(args, name, None) is None:
            setattr(args, name, DEFAULTS.get(args.workload, {}).get(name, value))
    if args.workload in ('zlib', 'actrail') and not args.project:
        raise ValueError(f'{args.workload} requires --project pointing to local source')
    if args.workload == 'mmap-contention' and args.concurrency < 2:
        raise ValueError('mmap-contention needs at least 2 threads')
    if args.workload == 'fork-migrate' and args.concurrency < 2:
        raise ValueError('fork-migrate needs at least 2 threads')
    return args


def build(name):
    import subprocess

    if name in NATIVE:
        folder = ROOT / 'workload/native'
        (folder / '.build').mkdir(exist_ok=True)
        subprocess.run(
            [
                'gcc',
                '-O2',
                '-g',
                '-std=c11',
                '-Wall',
                '-Wextra',
                '-Werror',
                '-pthread',
                str(folder / 'ops.c'),
                '-o',
                str(folder / '.build/ops'),
            ],
            check=True,
        )
    elif name == 'memory-pressure':
        folder = ROOT / 'workload/memory-pressure'
        (folder / '.build').mkdir(exist_ok=True)
        subprocess.run(
            [
                'gcc',
                '-O2',
                '-g',
                '-Wall',
                '-Wextra',
                '-Werror',
                '-Wno-misleading-indentation',
                '-pthread',
                str(folder / 'memory_scan.c'),
                '-o',
                str(folder / '.build/memory_scan'),
            ],
            check=True,
        )
    elif name == 'file-anon-pressure':
        folder = ROOT / 'workload/file-anon-pressure'
        subprocess.run(['python3', str(folder / 'prepare_workload.py')], check=True)
        (folder / '.build').mkdir(exist_ok=True)
        subprocess.run(
            [
                'g++',
                '-std=c++11',
                '-O3',
                '-pthread',
                '-fno-omit-frame-pointer',
                '-Wall',
                '-Wextra',
                str(folder / 'workload.cpp'),
                '-o',
                str(folder / '.build/workload'),
            ],
            check=True,
        )
    return 0
