from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from system.metrics import Reader, SystemMonitor, cpu_delta
from logutil import log_line

ROOT = Path(__file__).resolve().parents[2]


def fixture(folder, cpu='100 10 50 800 20 5 5 10 30 5', pressure_total=10000):
    (folder / 'pressure').mkdir(exist_ok=True)
    (folder / 'stat').write_text('cpu ' + cpu + '\ncpu0 1 2 3 4\ncpu1 1 2 3 4\n')
    (folder / 'meminfo').write_text(
        'MemTotal: 1024 kB\nMemAvailable: 256 kB\nMemFree: 128 kB\n'
        'Buffers: 16 kB\nCached: 64 kB\nSwapTotal: 512 kB\nSwapFree: 384 kB\n'
    )
    (folder / 'loadavg').write_text('1.50 2.50 3.50 2/100 999\n')
    for resource in ('cpu', 'memory', 'io'):
        (folder / 'pressure' / resource).write_text(
            f'some avg10=1.00 avg60=2.00 avg300=3.00 total={pressure_total}\n'
            f'full avg10=0.25 avg60=0.50 avg300=1.00 total={pressure_total//2}\n'
        )


class SystemMetricTests(unittest.TestCase):
    def test_runtime_logs_have_beijing_milliseconds_without_changing_stdout(self):
        output, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            log_line('first\nsecond', wall_time_ns=1700000000123456789)
        self.assertEqual(output.getvalue(), '')
        self.assertEqual(
            errors.getvalue(), '2023-11-15 06:13:20.123 first\n2023-11-15 06:13:20.123 second\n'
        )

    def test_system_log_timestamp_matches_sample_time_including_read_errors(self):
        with tempfile.TemporaryDirectory() as name:
            folder = Path(name)
            fixture(folder)
            (folder / 'pressure/cpu').unlink()
            monitor = SystemMonitor(1000, live=True, reader=Reader(folder))
            errors = io.StringIO()
            with patch(
                'system.metrics.time.time_ns', return_value=1700000000123456789
            ), redirect_stderr(errors):
                try:
                    monitor.start()
                    monitor.stop()
                    value = monitor.result()
                finally:
                    monitor.close()
            rows = errors.getvalue().splitlines()
            self.assertTrue(any('SYSTEM_UNAVAILABLE source=pressure/cpu' in row for row in rows))
            self.assertEqual(
                sum(' SYSTEM elapsed_s=' in row for row in rows), value['samples_total']
            )
            self.assertTrue(all(row.startswith('2023-11-15 06:13:20.123 ') for row in rows))
            self.assertTrue(
                all(sample['wall_time_ns'] == 1700000000123456789 for sample in value['samples'])
            )

    def test_cpu_excludes_duplicate_guest_and_psi_uses_actual_interval(self):
        with tempfile.TemporaryDirectory() as name:
            folder = Path(name)
            fixture(folder)
            reader = Reader(folder)
            with patch('system.metrics.time.monotonic_ns', return_value=1000000000):
                first = reader.read()
            self.assertIsNone(first['cpu']['utilization'])
            fixture(folder, cpu='140 10 70 830 30 5 5 10 50 5', pressure_total=20000)
            with patch('system.metrics.time.monotonic_ns', return_value=2000000000):
                second = reader.read()
            self.assertEqual(second['cpu']['logical_cpus'], 2)
            self.assertAlmostEqual(second['cpu']['utilization']['busy_percent'], 60)
            self.assertAlmostEqual(second['cpu']['utilization']['iowait_percent'], 10)
            self.assertAlmostEqual(second['memory']['used_percent'], 75)
            self.assertEqual(second['memory']['available_bytes'], 256 * 1024)
            self.assertEqual(second['memory']['swap_used_bytes'], 128 * 1024)
            self.assertAlmostEqual(second['psi']['memory']['some']['interval_percent'], 1)
            self.assertNotIn('full', second['psi']['cpu'])
            self.assertEqual(second['load']['runnable_tasks'], 2)
            self.assertFalse(second['errors'])

    def test_unavailable_and_malformed_sources_do_not_become_zero(self):
        with tempfile.TemporaryDirectory() as name:
            folder = Path(name)
            fixture(folder)
            (folder / 'pressure/cpu').unlink()
            (folder / 'stat').write_text('broken\n')
            (folder / 'meminfo').write_text('MemTotal: 1024 kB\n')
            value = Reader(folder).read()
            self.assertIsNone(value['cpu'])
            self.assertIsNone(value['psi']['cpu'])
            self.assertIsNone(value['memory']['used_percent'])
            self.assertIn('pressure/cpu', value['errors'])
            self.assertIn('stat', value['errors'])
            self.assertIsNotNone(value['psi']['memory'])

    def test_reset_cpu_counter_has_no_fake_utilization(self):
        before = dict.fromkeys(
            ('user', 'nice', 'system', 'idle', 'iowait', 'irq', 'softirq', 'steal'), 10
        )
        self.assertIsNone(cpu_delta(before, before))
        self.assertIsNone(cpu_delta(before, dict(before, idle=9, user=30)))

    def test_periodic_capture_has_bounded_memory_and_complete_jsonl(self):
        with tempfile.TemporaryDirectory() as name:
            folder = Path(name)
            fixture(folder)
            output = folder / 'host.jsonl'
            monitor = SystemMonitor(100, output=output, reader=Reader(folder), capacity=2)
            try:
                monitor.start()
                deadline = time.monotonic() + 2
                while monitor.samples_total < 3 and time.monotonic() < deadline:
                    time.sleep(0.01)
                monitor.stop()
                monitor.stop()
                value = monitor.result()
                self.assertGreaterEqual(value['samples_total'], 4)
                self.assertEqual(value['samples_retained'], 2)
                self.assertTrue(value['samples_truncated'])
                rows = [json.loads(line) for line in output.read_text().splitlines()]
                self.assertEqual(len(rows), value['samples_total'])
                self.assertEqual(rows[0]['monotonic_ns'], value['start_ns'])
                self.assertEqual(rows[-1]['monotonic_ns'], value['end_ns'])
                self.assertGreaterEqual(value['sampling_cpu_ns'], 0)
            finally:
                monitor.close()
            self.assertFalse(monitor.thread.is_alive())


@unittest.skipUnless(sys.platform == 'linux', 'Host metrics require Linux')
class LiveSystemMetricTests(unittest.TestCase):
    def test_independent_system_collector(self):
        with tempfile.TemporaryDirectory() as name:
            output = Path(name) / 'host.jsonl'
            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / 'lockbench.py'),
                    'system',
                    'run',
                    '--duration',
                    '.25',
                    '--system-interval-ms',
                    '100',
                    '--system-output',
                    str(output),
                ],
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            value = json.loads(result.stdout)
            self.assertTrue(value['enabled'])
            self.assertGreaterEqual(value['samples_total'], 3)
            self.assertIsNotNone(value['cpu_window'])
            self.assertGreater(value['sampling_cpu_ns'], 0)
            self.assertGreater(value['samples'][-1]['memory']['total_bytes'], 0)
            self.assertEqual(len(output.read_text().splitlines()), value['samples_total'])
            self.assertNotIn('OBSERVER_READY', result.stderr)

    @unittest.skipUnless(
        (ROOT / 'observer/mmap/fentry/dist/observer').exists(), 'Build lock observer first'
    )
    def test_independent_and_combined_sessions(self):
        base = [sys.executable, str(ROOT / 'lockbench.py')]
        options = ['--target', 'all', '--observe', 'off', '--duration', '.2']
        result = subprocess.run(
            [*base, 'observer', 'run', *options], capture_output=True, text=True, timeout=15
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('system', json.loads(result.stdout))
        self.assertNotIn('SYSTEM ', result.stderr)
        result = subprocess.run(
            [*base, 'run', *options, '--system-interval-ms', '100'],
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        value = json.loads(result.stdout)['collectors']
        self.assertEqual(set(value), {'locks', 'system'})
        self.assertEqual(set(value['locks']['objects']), {'mmap', 'cgroup', 'fork'})
        self.assertTrue(value['system']['enabled'])
        result = subprocess.run(
            [*base, 'run', *options, '--system', 'off'], capture_output=True, text=True, timeout=15
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(set(json.loads(result.stdout)['collectors']), {'locks'})


if __name__ == '__main__':
    unittest.main()
