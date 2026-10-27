"""Narrow map-insertion attribution, with independent warming and graph controls."""
import argparse
import ctypes
import json
import os
from pathlib import Path
import pwd
import random
import statistics
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
BASE = HERE.parent / 'mmap-cause-20261026'
sys.path.insert(0, str(BASE))
import importlib.util
spec = importlib.util.spec_from_file_location('cause_runner', BASE / 'run.py')
cause = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cause)
import warm_observer as warm
from trace_graph import MapGraph, GraphUnavailable
from graph_analysis import decode, LINE

GRAPH = False


def preflight_graph(out, local):
    directory = out / 'trace-preflight'
    directory.mkdir()
    graph = MapGraph(directory, [])
    lib = ctypes.CDLL('libbpf.so.1', use_errno=True)
    lib.bpf_map_create.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint,
                                  ctypes.c_uint, ctypes.c_uint, ctypes.c_void_p]
    fd = lib.bpf_map_create(1, b'map_positive', 4, 8, 16, None)
    if fd < 0:
        graph.close()
        raise OSError(ctypes.get_errno(), 'Cannot create positive-control map')
    try:
        graph.start()
        for i in range(8):
            key, value = ctypes.c_uint(i), ctypes.c_uint64(i)
            if lib.bpf_map_update_elem(fd, ctypes.byref(key), ctypes.byref(value), 1):
                raise OSError(ctypes.get_errno(), 'Cannot update positive-control map')
        metadata = graph.stop()
        text = (directory / 'map-function-graph.txt').read_text()
        tids = ({int(m.group(3)) for line in text.splitlines() if (m := LINE.match(line))}
                if local else {os.getpid()})
        parsed = decode(text, tids)
        assert parsed['roots'] >= 8 and not parsed['incomplete'] and not parsed['unparsed'], parsed
        assert parsed['functions'].get('alloc_htab_elem', {}).get('calls', 0) >= 8, parsed
        cause.dump(directory / 'positive-control.json', dict(metadata=metadata, **parsed))
    finally:
        graph.close()
        os.close(fd)


class Observer(warm.WarmObserver):
    def start(self):
        super().start()
        self.graph = None
        self.visible_tids = [int(p.name) for p in Path(f'/proc/{self.root_pid}/task').iterdir()]
        if GRAPH:
            # Function tracing reports initial-namespace TIDs. Keep raw records,
            # then select the measured cohort using identities exported by BPF.
            self.graph = MapGraph(self.directory, [])
            self.graph.start()

    def stop(self):
        metadata = None
        if self.graph:
            metadata = self.graph.stop()
            self.graph.close()
            self.graph = None
        super().stop()
        if metadata:
            identities = self.value['warming']['last_raw_identity_by_cpu']
            runtime = self.value['diagnostic']['runtime_identity']
            if runtime['pid_namespace_ino']:
                tids = {v['raw_tid'] for v in identities}
                if len(tids) != 1:
                    raise RuntimeError('Local graph validation expects one known worker TID')
            else:
                tids = set(self.visible_tids)
            metadata['cohort_raw_tids'] = sorted(tids)
            parsed = decode((self.directory / 'map-function-graph.txt').read_text(), tids)
            assert not parsed['incomplete'] and not parsed['unparsed'], parsed
            for text in metadata['per_cpu_stats'].values():
                for line in text.splitlines():
                    key, _, value = line.partition(':')
                    if key in ('overrun', 'commit overrun', 'dropped events'):
                        assert int(value.strip()) == 0, (key, value)
            if not parsed['roots']:
                raise RuntimeError('No graph roots: no inference about absence of contention is possible')
            self.value['map_graph'] = dict(metadata=metadata, **parsed)
            (self.directory / 'map-function-graph.json').write_text(json.dumps(self.value['map_graph'], indent=2))

    def close(self):
        try:
            if getattr(self, 'graph', None):
                self.graph.close()
                self.graph = None
        finally:
            super().close()


def summarize(out, rows):
    groups = []
    for name in sorted({row['case']['name'] for row in rows}):
        found = [row for row in rows if row['case']['name'] == name]
        groups.append(dict(name=name, rounds=len(found), insert_ns=cause.describe([
            next(c['mean_ns'] for c in row['diagnostic']['components'] if c['name'] == 'map_insert') for row in found]),
            total_ns=cause.describe([row['diagnostic']['mean_ns'] for row in found]),
            warm_ns=cause.describe([sum(s['ns'] for s in row['warming']['slots']) / row['diagnostic']['calls'] for row in found]),
            graph=[row['graph_summary'] for row in found if row.get('graph_summary')]))
    cause.dump(out / 'summary.json', groups)
    lines = ['Map mechanism controls, ns/call. Instrumented call averages, then median across rounds.',
             'Warming time is ADDITIONAL work, not a net optimization. Graph times include tracer overhead.',
             'case | insert | insertion MADN | total | warm additional']
    for row in groups:
        lines.append(f"{row['name']} | {row['insert_ns']['median']:.2f} | {row['insert_ns']['madn']:.2f} | {row['total_ns']['median']:.2f} | {row['warm_ns']['median']:.2f}")
        for g in row['graph']:
            lines.append('  trace: ' + json.dumps(g, ensure_ascii=False))
    (out / 'SUMMARY.txt').write_text('\n'.join(lines) + '\n')


def main():
    global GRAPH
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--local-smoke', action='store_true')
    parser.add_argument('--graph', choices=('auto', 'required', 'off'), default='auto')
    args = parser.parse_args()
    if os.geteuid():
        parser.error('Root is required for BPF and private function-graph tracing')
    cause.http_measure.guard_active_experiments()
    before = cause.flag()
    fd = -1
    if before != '1':
        if not args.local_smoke or os.uname().machine == 'aarch64':
            parser.error('Existing runtime statistics must be 1; no setting changed')
        lib = ctypes.CDLL('libbpf.so.1', use_errno=True)
        fd = lib.bpf_enable_stats(0)
        if fd < 0:
            raise OSError(ctypes.get_errno(), 'Cannot hold local statistics FD')
    out = Path(tempfile.mkdtemp(prefix=time.strftime('results-%Y%m%d-%H%M%S-'), dir=HERE))
    account = pwd.getpwuid(int(os.environ.get('SUDO_UID', os.getuid())))
    os.chown(out, account.pw_uid, account.pw_gid)
    out.chmod(0o755)
    metadata = dict(kernel=os.uname().release, machine=os.uname().machine, original_sysctl=before,
                    local_smoke=args.local_smoke, original_source='mmap-cause-20261026/source, observer 57326bc',
                    controlled='One worker, one fixed CPU, alternating mprotect with SHA before each pair; same workload for all warming controls',
                    graph='Private tracefs instance, selected hash/allocation/freelist/spinlock functions, all raw records retained and cohort selected afterwards',
                    purpose='Mechanism attribution only. No production change or claim of net savings from pre-warming.')
    cause.dump(out / 'metadata.json', metadata)
    rows = []
    print('RESULTS:', out, flush=True)
    cause.diagnostic.DiagnosticObserver = Observer
    cause.http_measure.NativeObserver = Observer
    schedule = []
    for repeat in range(1 if args.local_smoke else 3):
        modes = ['none', 'lookup-target', 'lookup-other', 'recycle-node', 'recycle-other']
        random.Random(20261026 + repeat).shuffle(modes)
        for mode in modes:
            schedule.append(dict(name='warm-' + mode, workload='native', mode=mode, graph=False,
                                 work='pair-hash', operations=128 if args.local_smoke else 2048, repeat=repeat))
    for work in ('pair-hot', 'pair-hash'):
        for graph in (False, True):
            schedule.append(dict(name=work + ('-graph' if graph else '-plain'), workload='native',
                                 mode='none', graph=graph, work=work,
                                 operations=64 if args.local_smoke else 512, repeat=0))
    if not args.local_smoke:
        for graph in (False, True):
            schedule.append(dict(name='http-32' + ('-graph' if graph else '-plain'), workload='http',
                                 mode='none', graph=graph, repeat=0))
    planned_runs = len(schedule)
    cause.dump(out / 'planned-schedule.json', schedule)
    try:
        try:
            if args.graph == 'off':
                raise GraphUnavailable('Disabled explicitly with --graph off')
            preflight_graph(out, args.local_smoke)
            graph_status = dict(supported=True, checks='POSITIVE_CONTROL_PASS')
            print('TRACE_PREFLIGHT_PASS: selected hash/allocation functions recorded in private instance', flush=True)
        except GraphUnavailable as exc:
            if args.graph == 'required':
                raise
            graph_status = dict(supported=False, reason=str(exc), missing_measurement='Internal function/lock-slowpath tracing')
            skipped = [case for case in schedule if not case['name'].startswith('warm-')]
            schedule = [case for case in schedule if case['name'].startswith('warm-')]
            cause.dump(out / 'skipped.json', dict(reason=str(exc), cases=skipped))
            print('TRACE_UNAVAILABLE: ' + str(exc), flush=True)
            print(f'CONTINUING_CONTROLS_ONLY: {len(schedule)} warming trials; {len(skipped)} graph/comparison trials explicitly skipped', flush=True)
        cause.dump(out / 'capabilities.json', dict(function_graph=graph_status))
        cause.dump(out / 'schedule.json', schedule)
        for case in schedule:
            assert cause.flag() == before, 'Statistics setting changed externally'
            warm.MODE = case['mode']
            warm.original.PAIRED = case['workload'] == 'native'
            GRAPH = case['graph']
            for key in ('DIAGNOSTIC_SERVICE_CPUS', 'DIAGNOSTIC_WORKLOAD_CPUS'):
                os.environ.pop(key, None)
            if case['workload'] == 'native':
                selected = dict(case, threads=1, paired=True)
                value = cause.native_measure(out, selected, case['repeat'], [min(os.sched_getaffinity(0))])
            else:
                cause.http_measure.CLIENTS = 32
                os.environ['HTTP_WORKERS'] = '32'
                value = cause.http_measure.measure(out, 'fentry', True, 0, 256, case['name'], before)
            observer = value.get('observation', value.get('observer'))
            graph = observer.get('map_graph')
            if graph and case['workload'] == 'native':
                # On the initial namespace, exclude the controller/main thread's
                # outstanding read operation and reconcile the worker directly.
                worker_ids = {i['raw_tid'] for i in observer['warming']['last_raw_identity_by_cpu']}
                scoped = [r for r in graph['records'] if r['tid'] in worker_ids]
                assert len(scoped) == case['operations'], (len(scoped), case['operations'])
                assert all(any(c['function'] == 'alloc_htab_elem' for c in r['children']) for r in scoped)
            record = dict(case=case, diagnostic=observer['diagnostic'], warming=observer['warming'],
                          measurement=value, graph_summary={name: entry for name, entry in graph['functions'].items()} if graph else None)
            rows.append(record)
            cause.dump(out / 'rows.json', rows)
            summarize(out, rows)
            assert cause.flag() == before, 'Statistics setting changed externally'
            print(f"[{len(rows)}/{len(schedule)}] {case['name']}: scoped={record['diagnostic']['calls']}; insertion={next(p['mean_ns'] for p in record['diagnostic']['components'] if p['name']=='map_insert'):.2f}ns", flush=True)
        cause.dump(out / 'completed.json', dict(checks='PASS' if graph_status['supported'] else 'PASS_CONTROLS_ONLY',
                                               runs=len(rows), expected_runs=len(schedule), planned_runs=planned_runs,
                                               graph_supported=graph_status['supported'], skipped_runs=planned_runs-len(schedule),
                                               original_sysctl=before, final_sysctl=cause.flag()))
        print('MAP_INTERNALS_COMPLETE', flush=True)
    except BaseException as exc:
        cause.dump(out / 'failure.json', dict(error=repr(exc), completed_runs=len(rows)))
        raise
    finally:
        if fd >= 0:
            os.close(fd)


if __name__ == '__main__':
    main()
