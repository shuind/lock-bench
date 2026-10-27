import argparse
import base64
import contextlib
import csv
import io
import json
import os
from pathlib import Path
import re
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest

from bench.analysis import analyze
from bench.cli import validate_observation
from bench.report import report
from workload.registry import ROOT


class AnalysisTests(unittest.TestCase):
    def fixture(self, folder, observe='on'):
        (folder / 'parameters.json').write_text(json.dumps(dict(repeats=3, observe=observe)))
        rows = []
        for repeat, delta in enumerate((1, 3, -1), 1):
            baseline = dict(
                schema_version=1,
                repeat=repeat,
                workload='mmap',
                observe=False,
                workload_cpu_ns=10000000,
                wall_ns=20000000,
                cpu_scope='fixture',
                result=dict(operations=100, unit='operations', wall_ns=20000000, metrics={}),
            )
            rows.append(baseline)
            if observe == 'on':
                probe = dict(
                    baseline,
                    observe=True,
                    workload_cpu_ns=(10 + delta) * 1000000,
                    observer_cpu_ns=10000,
                    controller_cpu_ns=20000,
                    observation=dict(
                        target='mmap',
                        counters=dict(
                            total_start=1600,
                            total_read_start=1000,
                            total_write_start=600,
                            match_start=400,
                            match_read_start=100,
                            match_write_start=300,
                            match_downgrade=10,
                        ),
                    ),
                )
                rows.append(probe)
        (folder / 'raw.jsonl').write_text(''.join(json.dumps(row) + '\n' for row in rows))
        return rows

    def test_pair_statistics_and_roundtrip(self):
        with tempfile.TemporaryDirectory() as name:
            folder = Path(name)
            self.fixture(folder)
            summary = analyze(folder)
            self.assertEqual(summary['statistics']['cpu_delta_ms']['rounds'], [1, 3, -1])
            self.assertEqual(summary['statistics']['cpu_delta_ms']['median'], 1)
            self.assertAlmostEqual(
                summary['statistics']['cpu_delta_ms']['madn'], 2 / 0.6744897501960817
            )
            self.assertEqual(summary['statistics']['mmap_match_start']['median'], 400)
            self.assertEqual(analyze(folder, write=False), summary)
            with (folder / 'rounds.csv').open() as stream:
                self.assertEqual(len(list(csv.DictReader(stream))), 3)

    def test_mmap_entry_rates_use_each_round_before_median(self):
        with tempfile.TemporaryDirectory() as name:
            folder = Path(name)
            rows = self.fixture(folder)
            probes = [row for row in rows if row['observe']]
            for row, total, matched in zip(probes, (100, 100, 10000), (10, 90, 200)):
                counts = row['observation']['counters']
                counts.update(
                    total_read_start=total,
                    total_start=total + counts['total_write_start'],
                    match_read_start=matched,
                    match_start=matched + counts['match_write_start'],
                )
            (folder / 'raw.jsonl').write_text(''.join(json.dumps(row) + '\n' for row in rows))
            summary = analyze(folder)
            stats = summary['statistics']
            self.assertEqual(stats['mmap_total_read_start']['median'], 100)
            self.assertEqual(stats['mmap_match_read_start']['median'], 90)
            self.assertEqual(stats['mmap_read_hit_percent']['rounds'], [10, 90, 2])
            self.assertEqual(stats['mmap_read_hit_percent']['median'], 10)
            destination = folder / 'report.html'
            with contextlib.redirect_stdout(io.StringIO()):
                report([folder], destination)
            self.assertIn(
                '<td>读</td><td>100</td><td>90</td><td>10.00%</td>',
                destination.read_text(encoding='utf-8'),
            )

    def test_missing_mmap_entry_counters_do_not_become_zero_or_partial_medians(self):
        with tempfile.TemporaryDirectory() as name:
            folder = Path(name)
            rows = self.fixture(folder)
            probe = next(row for row in rows if row['observe'])
            del probe['observation']['counters']['total_read_start']
            (folder / 'raw.jsonl').write_text(''.join(json.dumps(row) + '\n' for row in rows))
            summary = analyze(folder)
            self.assertIsNone(summary['paired_rounds'][0]['mmap_total_read_start'])
            self.assertNotIn('mmap_total_read_start', summary['statistics'])
            self.assertNotIn('mmap_read_hit_percent', summary['statistics'])
            destination = folder / 'report.html'
            with contextlib.redirect_stdout(io.StringIO()):
                report([folder], destination)
            self.assertIn(
                '<td>读</td><td>未记录</td><td>100</td><td>未记录</td>',
                destination.read_text(encoding='utf-8'),
            )

    def test_incomplete_or_duplicate_pair_rejected(self):
        with tempfile.TemporaryDirectory() as name:
            folder = Path(name)
            rows = self.fixture(folder)
            for damaged in (rows[:-1], rows + [rows[0]], rows[:-2]):
                (folder / 'raw.jsonl').write_text(
                    ''.join(json.dumps(row) + '\n' for row in damaged)
                )
                with self.assertRaises(ValueError):
                    analyze(folder)

    def test_baseline_only_has_no_overhead_claim(self):
        with tempfile.TemporaryDirectory() as name:
            folder = Path(name)
            self.fixture(folder, 'off')
            summary = analyze(folder)
            self.assertFalse(summary['observed'])
            self.assertNotIn('cpu_delta_ms', summary['statistics'])

    def test_report_preserves_tables_without_embedding_raw_data(self):
        with tempfile.TemporaryDirectory() as name:
            folder = Path(name)
            self.fixture(folder)
            summary = analyze(folder)
            destination = folder / 'report.html'
            raw = '<script id="report-data" type="application/json">{"measurement_records":[{"address":18446744073709551615}]}</script>'
            table = '<table><tr><td>Published result: 1.23 ms</td></tr></table>'
            downloads = '<div hidden id="downloads"><button id="download-json">JSON</button></div>'
            script = (
                '<script>JSON.parse(document.getElementById("report-data").textContent)</script>'
            )
            destination.write_text(
                '<html><body>' + table + raw + downloads + script + '</body></html>'
            )
            with contextlib.redirect_stdout(io.StringIO()):
                report([folder], destination)
                report([folder], destination)
                from bench.checks.verify_results import verify_report

                verify_report(destination)
            text = destination.read_text(encoding='utf-8')
            self.assertIn(table, text)
            self.assertNotIn('report-data', text)
            self.assertNotIn('measurement_records', text)
            self.assertNotIn('download-json', text)
            self.assertEqual(text.count('id="unified-bench-results"'), 1)
            encoded = re.search(r'href="data:application/json;base64,([^"]+)"', text)[1]
            self.assertEqual(json.loads(base64.b64decode(encoded)), summary)


class CliTests(unittest.TestCase):
    def test_observer_only_checkout_has_no_development_dependency(self):
        import shutil

        with tempfile.TemporaryDirectory() as name:
            folder = Path(name)
            shutil.copy2(ROOT / 'lockbench.py', folder / 'lockbench.py')
            for name in ('cli.py', 'session.py', 'logutil.py'):
                shutil.copy2(ROOT / name, folder / name)
            shutil.copytree(
                ROOT / 'observer',
                folder / 'observer',
                ignore=shutil.ignore_patterns('dist', '.build', '__pycache__'),
            )
            for arguments in (
                [],
                ['observer'],
                ['observer', 'build'],
                ['observer', 'run'],
                ['observer', 'inspect'],
            ):
                with self.subTest(arguments=arguments):
                    result = subprocess.run(
                        [sys.executable, str(folder / 'lockbench.py'), *arguments, '--help'],
                        cwd=folder,
                        text=True,
                        capture_output=True,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
            result = subprocess.run(
                [sys.executable, str(folder / 'lockbench.py'), '--help'],
                cwd=folder,
                text=True,
                capture_output=True,
            )
            self.assertNotIn('workload', result.stdout)
            self.assertNotIn('bench}', result.stdout)

    def test_public_help_and_removed_process_filters(self):
        for args in (
            [],
            ['observer'],
            ['workload'],
            ['bench'],
            ['bench', 'run'],
            ['workload', 'run'],
        ):
            p = subprocess.run(
                [sys.executable, str(ROOT / 'lockbench.py'), *args, '--help'],
                capture_output=True,
                text=True,
            )
            self.assertEqual(p.returncode, 0, p.stderr)
        p = subprocess.run(
            [sys.executable, str(ROOT / 'lockbench.py'), 'observer', 'run', '--pid', '1'],
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(p.returncode, 0)

    def test_fork_inherits_timeout_and_honors_override(self):
        base = dict(
            target='all',
            observe='on',
            scheme='fentry',
            collect='state',
            timeout='poll',
            poll_ms=100,
            threshold_ns=1000000000,
            rw='both',
        )
        for target in ('mmap', 'cgroup', 'fork'):
            for field in ('scheme', 'collect', 'timeout'):
                base[target + '_' + field] = None
        for timeout in ('poll', 'none'):
            selected = validate_observation(argparse.Namespace(**dict(base, timeout=timeout)))
            self.assertEqual({item.timeout for item in selected}, {timeout})
            self.assertTrue(all(item.object == item.backend.object for item in selected))
        selected = validate_observation(argparse.Namespace(**dict(base, fork_timeout='none')))
        self.assertEqual(
            {item.backend.target: item.timeout for item in selected},
            {'mmap': 'poll', 'cgroup': 'poll', 'fork': 'none'},
        )
        with self.assertRaisesRegex(ValueError, 'fork/kprobe has no timer'):
            validate_observation(argparse.Namespace(**dict(base, timeout='timer')))
        selected = validate_observation(
            argparse.Namespace(**dict(base, timeout='timer', fork_timeout='poll'))
        )
        self.assertEqual(
            {item.backend.target: item.timeout for item in selected},
            {'mmap': 'timer', 'cgroup': 'timer', 'fork': 'poll'},
        )
        for item in selected:
            expected = item.backend.timer_object if item.timeout == 'timer' else item.backend.object
            self.assertEqual(item.object, expected)
        with self.assertRaises(ValueError):
            validate_observation(argparse.Namespace(**dict(base, collect='count')))
        with self.assertRaises(ValueError):
            validate_observation(
                argparse.Namespace(**dict(base, target='mmap', scheme='kprobe', timeout='timer'))
            )

    def test_product_selection_and_independent_objects(self):
        from observer.catalog import select_products

        products = select_products()
        self.assertEqual(len(products), 8)
        self.assertEqual(len({item.binary for item in products}), 8)
        self.assertEqual(
            [item.id for item in select_products('mmap', 'tracepoint')], ['mmap/tracepoint']
        )
        self.assertEqual([item.id for item in select_products('fork')], ['fork/kprobe'])
        with self.assertRaises(ValueError):
            select_products('cgroup', 'raw')
        with self.assertRaises(ValueError):
            select_products('mmap', cgroup_scheme='fentry')

    def test_composite_stops_all_before_export_and_unwinds_failed_prepare(self):
        from observer.native import CompositeObserver

        calls = []

        class Child:
            def __init__(self, name, fail=False):
                self.name = name
                self.fail = fail

            def prepare(self):
                calls.append(self.name + ':prepare')
                if self.fail:
                    raise RuntimeError('load failed')

            def request_stop(self):
                calls.append(self.name + ':stop')

            def finish_stop(self):
                calls.append(self.name + ':export')

            def close(self):
                calls.append(self.name + ':close')

        composite = CompositeObserver([Child('a'), Child('b')])
        composite.stop()
        self.assertEqual(calls, ['a:stop', 'b:stop', 'a:export', 'b:export'])
        calls.clear()
        with self.assertRaises(RuntimeError):
            CompositeObserver([Child('a'), Child('b', True)]).prepare()
        self.assertEqual(calls, ['a:prepare', 'b:prepare', 'b:close', 'a:close'])


@unittest.skipUnless(
    sys.platform == 'linux' and (ROOT / 'workload/native/.build/ops').exists(),
    'Build Linux workloads first',
)
class LinuxIntegrationTests(unittest.TestCase):
    def run_cli(self, *args, timeout=25):
        p = subprocess.run(
            [sys.executable, str(ROOT / 'lockbench.py'), *args],
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=timeout,
        )
        self.assertEqual(p.returncode, 0, p.stderr + '\n' + p.stdout)
        return p

    def test_native_loads_and_fixed_work(self):
        with tempfile.TemporaryDirectory() as name:
            for workload in ('mmap', 'mprotect', 'read-maps', 'fault', 'fork', 'mmap-contention'):
                with self.subTest(workload=workload):
                    p = self.run_cli(
                        'workload',
                        'run',
                        '--workload',
                        workload,
                        '--operations',
                        '12',
                        '--concurrency',
                        '2',
                        '--anon-mib',
                        '1',
                        '--workdir',
                        str(Path(name) / workload),
                    )
                    value = json.loads(p.stdout.splitlines()[-1])
                    self.assertEqual(value['operations'], 12)
                    self.assertTrue(value['verified'])

    def test_http_and_page_scanning(self):
        with tempfile.TemporaryDirectory() as name:
            for workload, extra in [
                ('http', ['--operations', '2']),
                ('http-file', ['--operations', '8', '--file-mib', '1']),
                (
                    'memory-pressure',
                    [
                        '--operations',
                        '2',
                        '--file-mib',
                        '1',
                        '--anon-mib',
                        '1',
                        '--memory-limit-mib',
                        '0',
                    ],
                ),
            ]:
                with self.subTest(workload=workload):
                    p = self.run_cli(
                        'workload',
                        'run',
                        '--workload',
                        workload,
                        '--concurrency',
                        '2',
                        '--workdir',
                        str(Path(name) / workload),
                        *extra
                    )
                    self.assertTrue(json.loads(p.stdout.splitlines()[-1])['verified'])

    def test_baseline_bench_and_analysis(self):
        with tempfile.TemporaryDirectory() as name:
            self.run_cli(
                'bench',
                'run',
                '--workload',
                'mmap',
                '--observe',
                'off',
                '--operations',
                '200',
                '--repeats',
                '2',
                '--output',
                name,
            )
            folder = next(Path(name).glob('run-*'))
            summary = json.loads((folder / 'summary.json').read_text())
            self.assertEqual(summary['pairs'], 2)
            self.assertFalse(summary['observed'])
            self.run_cli('bench', 'check', '--input', str(folder))

    def test_file_anon_pressure_protocol_on_small_data(self):
        if not (ROOT / 'workload/file-anon-pressure/.build/workload').exists():
            self.skipTest('Build C++ workload first')
        with tempfile.TemporaryDirectory() as name:
            p = self.run_cli(
                'workload',
                'run',
                '--workload',
                'file-anon-pressure',
                '--duration',
                '.3',
                '--file-mib',
                '8',
                '--anon-mib',
                '2',
                '--file-threads',
                '2',
                '--memory-threads',
                '2',
                '--memory-limit-mib',
                '0',
                '--cpu-limit',
                '0',
                '--workdir',
                name,
            )
            value = json.loads(p.stdout.splitlines()[-1])
            self.assertGreater(value['metrics']['progress']['memory_node_visits'], 0)
            self.assertGreater(value['operations'], 0)

    def test_clean_build_adapter(self):
        import shutil

        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            source = root / 'zlib'
            source.mkdir()
            (source / 'configure').write_text('exit 0\n')
            (source / 'part.c').write_text('int part(void){return 1;}\n')
            (source / 'Makefile').write_text(
                'all: libz.a\nlibz.a: part.c\n\t$(CC) -c part.c -o part.o\n\tar rcs libz.a part.o\ndistclean:\n\trm -f part.o libz.a\n'
            )
            p = self.run_cli(
                'workload',
                'run',
                '--workload',
                'zlib',
                '--project',
                str(source),
                '--workdir',
                str(root / 'zlib-out'),
                '--concurrency',
                '2',
            )
            self.assertEqual(json.loads(p.stdout.splitlines()[-1])['operations'], 1)
            if not (shutil.which('cargo') or (Path.home() / '.cargo/bin/cargo').exists()):
                return
            source = root / 'actrail'
            (source / 'src').mkdir(parents=True)
            (source / 'Cargo.toml').write_text(
                '[package]\nname="ctl"\nversion="0.1.0"\nedition="2021"\n'
            )
            (source / 'src/main.rs').write_text('fn main(){println!("ok");}\n')
            p = self.run_cli(
                'workload',
                'run',
                '--workload',
                'actrail',
                '--project',
                str(source),
                '--workdir',
                str(root / 'actrail-out'),
                '--concurrency',
                '2',
            )
            self.assertEqual(json.loads(p.stdout.splitlines()[-1])['operations'], 1)
            self.assertFalse((source / 'target').exists())

    def test_observer_gate_without_loading_bpf(self):
        binary = ROOT / 'observer/mmap/fentry/dist/observer'
        if not binary.exists():
            self.skipTest('Build observer first')
        parent, child = socket.socketpair()
        p = subprocess.Popen(
            [str(binary), 'run', '--observe', 'off'],
            env=dict(os.environ, LOCKBENCH_CONTROL_FD=str(child.fileno())),
            pass_fds=(child.fileno(),),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        child.close()
        parent.settimeout(5)
        try:
            self.assertEqual(parent.recv(1), b'R')
            self.assertIsNone(p.poll())
            parent.sendall(b'G')
            self.assertEqual(parent.recv(1), b'A')
            time.sleep(0.02)
            parent.sendall(b'D')
            out, err = p.communicate(timeout=8)
            self.assertEqual(p.returncode, 0, err)
            value = json.loads(out)
            self.assertEqual(value['stop_reason'], 'controller')
            self.assertFalse(value['bpf_loaded'])
            self.assertEqual(value['collect'], 'stack')
            self.assertEqual(value['timeout'], 'poll')
            self.assertEqual(value['threshold_ns'], 100000000)
            log_rows = err.splitlines()
            self.assertEqual(len(log_rows), 2)
            for row in log_rows:
                self.assertRegex(row, r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3} ')
            self.assertIn('OBSERVER_READY ', log_rows[0])
            self.assertIn('OBJECT_CONFIG ', log_rows[1])
        finally:
            parent.close()
            if p.poll() is None:
                p.kill()
                p.wait()

    def test_shared_observer_options_and_resolution(self):
        from observer.catalog import select_products

        for backend in select_products():
            binary = backend.binary
            help_text = subprocess.check_output([str(binary), '--help'], text=True)
            native_options = set(re.findall(r'--([a-z-]+)', help_text))
            self.assertEqual(
                native_options,
                {
                    'observe',
                    'duration',
                    'collect',
                    'timeout',
                    'threshold-ns',
                    'poll-ms',
                    'rw',
                    'object',
                    'help',
                },
            )
            defaults = subprocess.run(
                [str(binary), 'run', '--observe', 'off', '--duration', '.001'],
                text=True,
                capture_output=True,
            )
            self.assertEqual(defaults.returncode, 0, defaults.stderr)
            value = json.loads(defaults.stdout)
            self.assertTrue({'actors', 'actors_retention', 'actors_capacity'}.isdisjoint(value))
            self.assertNotIn('actors_dropped', value['counters'])
            self.assertEqual(value['collect'], 'stack')
            self.assertEqual(value['timeout'], 'poll')
            self.assertEqual(value['threshold_ns'], 100000000)
            for collect, timeout in [
                ('count', 'none'),
                ('state', 'none'),
                ('stack', 'poll'),
                ('state', 'timer'),
            ]:
                p = subprocess.run(
                    [
                        str(binary),
                        'run',
                        '--observe',
                        'off',
                        '--collect',
                        collect,
                        '--timeout',
                        timeout,
                        '--duration',
                        '.001',
                    ],
                    text=True,
                    capture_output=True,
                )
                if timeout == 'timer' and not backend.timer:
                    self.assertNotEqual(p.returncode, 0)
                    continue
                self.assertEqual(p.returncode, 0, p.stderr)
                value = json.loads(p.stdout)
                self.assertEqual(
                    (value['target'], value['scheme'], value['collect'], value['timeout']),
                    (backend.target, backend.method, collect, timeout),
                )
                expected = backend.timer_object if timeout == 'timer' else backend.object
                self.assertEqual(value['object'], str(expected))

    def test_backend_objects_contain_only_own_hooks_and_maps(self):
        from observer.catalog import select_products

        for item in select_products():
            value = json.loads(subprocess.check_output([str(item.binary), 'inspect'], text=True))
            self.assertEqual({p['name'] for p in value['programs']}, set(item.programs))
            maps = {m['name'] for m in value['maps']}
            self.assertNotIn('actors', maps)
            counters = next(m for m in value['maps'] if m['name'] == 'counters')
            self.assertEqual(counters['max_entries'], 1)
            self.assertGreater(counters['value_size'], 8)
            self.assertNotIn('events', maps)
            if item.target == 'mmap':
                self.assertIn('mm_records', maps)
                self.assertTrue({'mm_owned', 'mm_states'}.isdisjoint(maps))
                record_map = next(m for m in value['maps'] if m['name'] == 'mm_records')
                self.assertEqual((record_map['key_size'], record_map['value_size']), (32, 32))
                self.assertNotIn('owned', maps)
            else:
                self.assertIn('owned', maps)
                self.assertNotIn('mm_owned', maps)
            self.assertFalse({'timers', 'mm_timers'} & maps)
            if item.timer:
                timed = json.loads(
                    subprocess.check_output(
                        [
                            str(item.binary),
                            'inspect',
                            '--object',
                            str(item.timer_object),
                        ],
                        text=True,
                    )
                )
                self.assertEqual({p['name'] for p in timed['programs']}, set(item.programs))
                self.assertTrue({'timers', 'mm_timers'} & {m['name'] for m in timed['maps']})
                self.assertIn('events', {m['name'] for m in timed['maps']})
                self.assertNotIn('actors', {m['name'] for m in timed['maps']})
        p = subprocess.run(
            [
                str(ROOT / 'observer/mmap/fentry/dist/observer'),
                'run',
                '--observe',
                'on',
                '--object',
                str(ROOT / 'observer/mmap/kprobe/dist/observer.bpf.o'),
            ],
            text=True,
            capture_output=True,
        )
        self.assertNotEqual(p.returncode, 0)
        self.assertEqual(json.loads(p.stdout)['error'], 71)  # EPROTO, before loading BPF.
        backend = next(item for item in select_products('mmap', 'fentry'))
        p = subprocess.run(
            [
                str(backend.binary),
                'run',
                '--observe',
                'on',
                '--timeout',
                'timer',
                '--object',
                str(backend.object),
            ],
            text=True,
            capture_output=True,
        )
        self.assertNotEqual(p.returncode, 0)
        self.assertEqual(json.loads(p.stdout)['error'], 95)  # ENOTSUP, before loading BPF.
        self.assertIn('observer.timer.bpf.o', p.stderr)

    def test_non_timer_objects_use_older_helpers_and_plain_exit_event(self):
        from observer.catalog import select_products

        # Helpers used by these programs, all present in mainline 5.10.
        allowed = {1, 2, 3, 5, 14, 27, 35, 113, 120, 131, 132}
        for item in select_products():
            with self.subTest(backend=item.id):
                data = item.object.read_bytes()
                self.assertEqual(data[:6], b'\x7fELF\x02\x01')
                offset = struct.unpack_from('<Q', data, 40)[0]
                size, count = struct.unpack_from('<HH', data, 58)
                helpers = set()
                for index in range(count):
                    section = struct.unpack_from('<IIQQQQIIQQ', data, offset + index * size)
                    if not section[2] & 4:  # SHF_EXECINSTR
                        continue
                    for position in range(section[4], section[4] + section[5], 8):
                        opcode, registers, _, immediate = struct.unpack_from(
                            '<BBhi', data, position
                        )
                        if opcode == 0x85 and registers >> 4 == 0:  # helper, not subprogram call
                            helpers.add(immediate)
                self.assertTrue(helpers)
                self.assertLessEqual(helpers, allowed)
                value = json.loads(
                    subprocess.check_output([str(item.binary), 'inspect'], text=True)
                )
                if item.id == 'mmap/kprobe':
                    hook = next(
                        program for program in value['programs'] if program['name'] == 'mx_exit'
                    )
                    self.assertEqual(hook['section'], 'tp/sched/sched_process_exit')
                elif item.target == 'mmap':
                    self.assertNotIn('mx_exit', {p['name'] for p in value['programs']})

    def test_live_cache_wait_and_batch_fallback(self):
        from observer.build import compiler

        with tempfile.TemporaryDirectory() as name:
            binary = Path(name) / 'runtime-checks'
            subprocess.run(
                [
                    compiler('CC', ('gcc', 'cc', 'clang')),
                    '-O2',
                    '-Wall',
                    '-Wextra',
                    '-Werror',
                    '-Wno-unused-parameter',
                    '-Wno-misleading-indentation',
                    '-I' + str(ROOT / 'observer/common'),
                    str(ROOT / 'bench/tests/runtime_checks.c'),
                    '-o',
                    str(binary),
                    '-lbpf',
                    '-lelf',
                    '-lz',
                ],
                check=True,
            )
            modes = [('dedup',), ('wait',)]
            if os.geteuid() == 0:
                modes.append(('scan', str(ROOT / 'observer/fork/kprobe/dist/observer.bpf.o')))
                modes.append(('mmap', str(ROOT / 'observer/mmap/kprobe/dist/observer.bpf.o')))
            for mode in modes:
                with self.subTest(mode=mode[0]):
                    result = subprocess.run(
                        [str(binary), *mode], text=True, capture_output=True, timeout=15
                    )
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr[-6000:])
                    self.assertIn('_PASS', result.stdout)
                    if mode[0] == 'scan':
                        self.assertEqual(result.stderr.count('STACK_WARNING '), 1)

    @unittest.skipUnless(hasattr(os, 'geteuid') and os.geteuid() == 0, 'Requires root for BPF')
    def test_small_stack_storage_warns_without_losing_lock_state(self):
        from observer.build import compiler
        from observer.catalog import Selection, backends
        from observer.native import NativeObserver

        with tempfile.TemporaryDirectory() as name:
            folder = Path(name)
            item = backends()['mmap/kprobe']
            obj = folder / 'small.bpf.o'
            arch = 'arm64' if os.uname().machine == 'aarch64' else 'x86'
            subprocess.run(
                [
                    compiler('CLANG', ('clang',)),
                    '-g',
                    '-O2',
                    '-target',
                    'bpf',
                    '-D__TARGET_ARCH_' + arch,
                    '-DSTACK_PRIMARY_CAPACITY=1',
                    '-DSTACK_OVERFLOW_CAPACITY=1',
                    '-I' + str(ROOT / 'observer/.build'),
                    '-I' + str(ROOT / 'observer/common'),
                    '-c',
                    str(item.directory / 'probe.bpf.c'),
                    '-o',
                    str(obj),
                ],
                check=True,
            )
            selected = Selection(item, True, 'stack', 'poll', 100000000, 100, 'both', 10, obj)
            observer = NativeObserver(selected, folder / 'observer')
            try:
                observer.prepare()
                observer.start()
                for mode in ('mmap', 'mprotect', 'read-maps'):
                    result = subprocess.run(
                        [str(ROOT / 'workload/native/.build/ops'), mode, '100', '5', '1', '4096'],
                        input='GF',
                        text=True,
                        capture_output=True,
                        timeout=10,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                observer.stop()
                result = observer.result()
                self.assertEqual(result['stack_capacity'], 2)
                self.assertTrue(result['stack_warning_emitted'])
                self.assertGreater(result['counters']['stack_errors'], 0)
                self.assertLessEqual(result['stack_entries'], 2)
                for counter in ('state_errors', 'pair_errors'):
                    self.assertEqual(result['counters'][counter], 0)
                self.assertEqual(result['owned_entries'], 0)
                self.assertEqual(result['state_entries'], 0)
                self.assertEqual(
                    result['counters']['match_start'],
                    result['counters']['match_read_start']
                    + result['counters']['match_write_start'],
                )
                log = (folder / 'observer/observer.log').read_text()
                self.assertEqual(log.count('STACK_WARNING '), 1)
            finally:
                observer.close()

    @unittest.skipUnless(hasattr(os, 'geteuid') and os.geteuid() == 0, 'Requires root for BPF')
    def test_mmap_methods_and_timer_delivery(self):
        from observer.catalog import Selection, backends
        from observer.native import NativeObserver

        with tempfile.TemporaryDirectory() as name:
            for method in ('fentry', 'kprobe', 'tracepoint', 'raw', 'timer'):
                item = backends()['mmap/' + ('fentry' if method == 'timer' else method)]
                timer = method == 'timer'
                selected = Selection(
                    item,
                    True,
                    'state',
                    'timer' if timer else 'poll',
                    1 if timer else 100000000,
                    100,
                    'both',
                    15,
                    item.timer_object if timer else item.object,
                )
                observer = NativeObserver(selected, Path(name) / method)
                with self.subTest(method=method):
                    try:
                        observer.prepare()
                        observer.start()
                        for mode in ('mmap', 'read-maps', 'mmap-contention'):
                            result = subprocess.run(
                                [
                                    str(ROOT / 'workload/native/.build/ops'),
                                    mode,
                                    '1000' if timer else '100',
                                    '10',
                                    '2' if mode == 'mmap-contention' else '1',
                                    '4194304' if mode == 'mmap-contention' else '4096',
                                ],
                                input='GF',
                                text=True,
                                capture_output=True,
                                timeout=15,
                            )
                            self.assertEqual(result.returncode, 0, result.stderr)
                        observer.stop()
                        value = observer.result()
                        self.assertEqual(value['ring_buffer_bytes'], 4194304 if timer else 0)
                        for key in ('pair_errors', 'state_errors', 'timer_errors'):
                            self.assertEqual(value['counters'][key], 0)
                        self.assertGreater(value['counters']['match_read_start'], 0)
                        self.assertGreater(value['counters']['match_write_start'], 0)
                        if timer:
                            self.assertGreater(value['counters']['timer_fired'], 0)
                            self.assertGreater(value['timeout_events_received'], 0)
                            self.assertGreater(value['live_reports'], 0)
                        else:
                            self.assertFalse(value['timeout_events_received'])
                    finally:
                        observer.close()

    @unittest.skipUnless(hasattr(os, 'geteuid') and os.geteuid() == 0, 'Requires root for BPF')
    def test_fork_collection_without_identity_table(self):
        from observer.catalog import Selection, backends
        from observer.native import NativeObserver

        with tempfile.TemporaryDirectory() as name:
            item = backends()['fork/kprobe']
            selected = Selection(
                item, True, 'stack', 'poll', 100000000, 100, 'both', 10, item.object
            )
            observer = NativeObserver(selected, Path(name))
            try:
                observer.prepare()
                observer.start()
                result = subprocess.run(
                    [str(ROOT / 'workload/native/.build/ops'), 'fork', '200', '5', '1', '4096'],
                    input='GF',
                    text=True,
                    capture_output=True,
                    timeout=10,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                observer.stop()
                value = observer.result()
                self.assertNotIn('actors', value)
                self.assertNotIn('actors_dropped', value['counters'])
                self.assertGreaterEqual(value['counters']['match_start'], 200)
                self.assertEqual(value['counters']['match_start'], value['counters']['match_end'])
                self.assertEqual(value['counters']['pair_errors'], 0)
                self.assertEqual(value['counters']['state_errors'], 0)
                self.assertEqual(value['owned_entries'], 0)
                self.assertEqual(value['state_entries'], 0)
                self.assertGreater(value['stack_entries'], 0)
            finally:
                observer.close()

    def test_composite_public_run_without_bpf(self):
        p = self.run_cli(
            'observer', 'run', '--target', 'all', '--observe', 'off', '--duration', '.02'
        )
        value = json.loads(p.stdout)
        self.assertEqual(set(value['objects']), {'mmap', 'cgroup', 'fork'})
        self.assertEqual(value['objects']['mmap']['scheme'], 'tracepoint')
        self.assertEqual(value['objects']['cgroup']['scheme'], 'fentry')
        self.assertFalse(value['observe'])
        self.assertTrue(all(not item['bpf_loaded'] for item in value['objects'].values()))
        for target, item in value['objects'].items():
            self.assertEqual(item['collect'], 'stack')
            self.assertEqual(item['timeout'], 'poll')
            self.assertEqual(item['threshold_ns'], 100000000)

    def test_bench_uses_injected_observer_contract(self):
        from bench.runner import measure

        calls = []

        class FakeObserver:
            def prepare(self):
                calls.append('prepare')

            def start(self):
                calls.append('start')

            def cpu_ns(self):
                calls.append('cpu')
                return len(calls) * 1000

            def stop(self):
                calls.append('stop')

            def result(self):
                calls.append('result')
                return dict(
                    target='mmap',
                    counters=dict.fromkeys(
                        (
                            'state_errors',
                            'pair_errors',
                            'stack_errors',
                            'timer_errors',
                            'ring_dropped',
                        ),
                        0,
                    ),
                    retprobe_misses=0,
                    live_poll_errors=0,
                )

            def close(self):
                calls.append('close')

        args = argparse.Namespace(
            workload='mmap',
            operations=12,
            duration=None,
            concurrency=1,
            file_mib=None,
            anon_mib=None,
            file_threads=None,
            memory_threads=None,
            memory_limit_mib=None,
            cpu_limit=None,
            project=None,
            run_timeout=20,
        )
        from workload.registry import resolve

        resolve(args)
        with tempfile.TemporaryDirectory() as name:
            row = measure(args, Path(name) / 'measurement', True, lambda directory: FakeObserver())
        self.assertEqual(calls, ['prepare', 'start', 'cpu', 'cpu', 'stop', 'result', 'close'])
        self.assertEqual(row['observer_cpu_ns'], 1000)


if __name__ == '__main__':
    unittest.main()
