"""Only private cgroups are created or changed; workload descendants inherit them."""

import json
import os
from pathlib import Path
import signal
import time
import uuid
from system.metrics import snapshot as host_snapshot


class Resources:
    def __init__(self, args):
        self.args = args
        self.paths = []
        self.children = []
        self.cpu = None
        self.memory = None
        self.version = 0
        self.name = 'lockbench-' + uuid.uuid4().hex[:12]

    def create(self):
        root = Path('/sys/fs/cgroup')
        limit = self.args.memory_limit_mib * 1024**2
        if os.geteuid() != 0:
            if limit or self.args.cpu_limit or 'migrate' in self.args.workload:
                raise PermissionError('Memory/CPU limits and migration workloads require sudo')
            return self
        uid = int(os.environ.get('SUDO_UID', os.getuid()))
        gid = int(os.environ.get('SUDO_GID', os.getgid()))
        try:
            if (root / 'cgroup.controllers').exists():
                self.version = 2
                p = root / self.name
                p.mkdir()
                self.paths.append(p)
                self.cpu = self.memory = p
                if not (p / 'cpu.stat').exists():
                    raise RuntimeError(
                        'Enable the cgroup v2 cpu controller before running experiments'
                    )
                if limit:
                    if not (p / 'memory.max').exists():
                        raise RuntimeError('Enable the cgroup v2 memory controller')
                    (p / 'memory.max').write_text(str(limit))
                    (p / 'memory.swap.max').write_text('0')
                if self.args.cpu_limit:
                    (p / 'cpu.max').write_text(f'{int(self.args.cpu_limit*100000)} 100000')
            else:
                self.version = 1
                parent = next((p for p in root.iterdir() if (p / 'cpuacct.usage').exists()), None)
                if parent is None:
                    raise RuntimeError('A cgroup cpuacct controller is required')
                self.cpu = parent / self.name
                self.cpu.mkdir()
                self.paths.append(self.cpu)
                if self.args.cpu_limit:
                    if not (self.cpu / 'cpu.cfs_quota_us').exists():
                        raise RuntimeError('CPU quota controller is unavailable')
                    (self.cpu / 'cpu.cfs_period_us').write_text('100000')
                    (self.cpu / 'cpu.cfs_quota_us').write_text(
                        str(int(self.args.cpu_limit * 100000))
                    )
                if limit:
                    self.memory = root / 'memory' / self.name
                    self.memory.mkdir()
                    self.paths.append(self.memory)
                    if not (self.memory / 'memory.memsw.limit_in_bytes').exists():
                        raise RuntimeError('The v1 memory+swap limit is required')
                    (self.memory / 'memory.limit_in_bytes').write_text(str(limit))
                    (self.memory / 'memory.memsw.limit_in_bytes').write_text(str(limit))
                    (self.memory / 'memory.swappiness').write_text('0')
            if 'migrate' in self.args.workload:
                if self.version == 2:
                    # Leave the empty parent as a domain, and put every task in a leaf.
                    (self.cpu / 'cgroup.subtree_control').write_text(
                        '+cpu' + (' +memory' if limit else '')
                    )
                for label in ('a', 'b'):
                    p = self.cpu / label
                    p.mkdir()
                    self.children.append(p)
                    os.chown(p / 'cgroup.procs', uid, gid)
                if self.version == 2:
                    os.chown(self.cpu / 'cgroup.procs', uid, gid)
            return self
        except BaseException:
            self.close()
            raise

    def environment(self):
        groups = list(self.paths)
        if self.children:
            groups = [p for p in groups if p != self.cpu] + [self.children[0]]
        env = {'LOCKBENCH_CGROUPS': json.dumps([str(p) for p in groups])}
        if self.children:
            env.update(
                LOCKBENCH_CGROUP_A=str(self.children[0] / 'cgroup.procs'),
                LOCKBENCH_CGROUP_B=str(self.children[1] / 'cgroup.procs'),
            )
        return env

    def snapshot(self):
        result = {}
        if self.cpu:
            if self.version == 1:
                result['cpu_ns'] = int((self.cpu / 'cpuacct.usage').read_text())
            else:
                values = dict(
                    line.split() for line in (self.cpu / 'cpu.stat').read_text().splitlines()
                )
                result['cpu_ns'] = int(values['usage_usec']) * 1000
        if self.memory:
            names = (
                'memory.stat',
                'memory.events',
                'memory.current',
                'memory.peak',
                'memory.swap.current',
                'memory.usage_in_bytes',
                'memory.max_usage_in_bytes',
                'memory.failcnt',
                'memory.memsw.failcnt',
                'memory.oom_control',
            )
            for name in names:
                if (self.memory / name).exists():
                    result[name] = (self.memory / name).read_text().strip()
        return result

    def close(self):
        # Only PIDs still resident in these newly created, uniquely named groups.
        for group in [*self.children, *self.paths]:
            if not group.exists():
                continue
            for text in (group / 'cgroup.procs').read_text().split():
                pid = int(text)
                if pid == os.getpid():
                    raise RuntimeError('Refusing to signal experiment controller')
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        for group in [*reversed(self.children), *reversed(self.paths)]:
            if not group.exists():
                continue
            for attempt in range(50):
                try:
                    group.rmdir()
                    break
                except OSError:
                    if attempt == 49:
                        raise
                    time.sleep(0.02)


def enter_workload():
    import resource

    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    target = 8192 if hard == resource.RLIM_INFINITY else min(8192, hard)
    if soft < target:
        resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))
    for group in json.loads(os.environ.get('LOCKBENCH_CGROUPS', '[]')):
        (Path(group) / 'cgroup.procs').write_text(str(os.getpid()))
    if os.geteuid() == 0 and int(os.environ.get('SUDO_UID', '0')):
        import pwd

        uid = int(os.environ['SUDO_UID'])
        account = pwd.getpwuid(uid)
        os.setgroups([])
        os.setgid(account.pw_gid)
        os.setuid(uid)
        os.environ.update(HOME=account.pw_dir, USER=account.pw_name, LOGNAME=account.pw_name)


def own_directory(path):
    if os.geteuid() == 0:
        os.chown(path, int(os.environ.get('SUDO_UID', '0')), int(os.environ.get('SUDO_GID', '0')))
