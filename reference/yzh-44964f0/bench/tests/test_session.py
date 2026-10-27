from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from session import run

ROOT = Path(__file__).resolve().parents[2]


class SessionTests(unittest.TestCase):
    def test_unlimited_session_survives_old_deadline_and_exports_on_interrupt(self):
        calls = []
        now = [0]

        class Collector:
            def prepare(self):
                calls.append('prepare')

            def start(self):
                calls.append('start')

            def cpu_ns(self):
                now[0] += 11
                calls.append('cpu')
                if now[0] >= 33:
                    raise KeyboardInterrupt
                return 0

            def stop(self):
                calls.append('stop')

            def result(self):
                calls.append('result')
                return {'exported': True}

            def close(self):
                calls.append('close')

        with patch('session.time.monotonic', side_effect=lambda: now[0]), patch(
            'session.time.monotonic_ns', side_effect=lambda: now[0] * 10**9
        ), patch('session.time.sleep'):
            result = run({'locks': Collector()})
        self.assertEqual(
            calls, ['prepare', 'start', 'cpu', 'cpu', 'cpu', 'stop', 'result', 'close']
        )
        self.assertEqual(result['stop_reason'], 'signal')
        self.assertEqual(result['collectors'], {'locks': {'exported': True}})
        self.assertEqual(result['end_ns'], 33 * 10**9)

    def test_observation_commands_default_to_unlimited_and_keep_explicit_limit(self):
        import lockbench
        from observer.catalog import resolve

        for command, handler in (
            (['run'], 'lockbench.combined_run'),
            (['observer', 'run'], 'observer.cli.observer_run'),
            (['system', 'run'], 'system.cli.run'),
        ):
            for flags, expected in (([], None), (['--duration', '30'], 30.0)):
                with self.subTest(command=command, flags=flags), patch(
                    handler, return_value=0
                ) as run_command:
                    self.assertEqual(lockbench.main(command + flags), 0)
                    args = run_command.call_args.args[0]
                    self.assertEqual(args.duration, expected)
                    if command != ['system', 'run']:
                        selection = resolve(args)[0]
                        self.assertEqual(selection.duration, expected)
                        self.assertEqual('--duration' in selection.command(), expected is not None)

    def test_default_methods_and_explicit_overrides_are_shared_by_observation_commands(self):
        import lockbench
        from observer.catalog import resolve

        cases = (
            ([], {'mmap': 'tracepoint', 'cgroup': 'fentry', 'fork': 'kprobe'}),
            (['--scheme', 'fentry'], {'mmap': 'fentry', 'cgroup': 'fentry', 'fork': 'kprobe'}),
            (['--scheme', 'kprobe'], {'mmap': 'kprobe', 'cgroup': 'kprobe', 'fork': 'kprobe'}),
            (['--mmap-scheme', 'raw'], {'mmap': 'raw', 'cgroup': 'fentry', 'fork': 'kprobe'}),
            (
                [
                    '--scheme',
                    'kprobe',
                    '--mmap-scheme',
                    'tracepoint',
                    '--cgroup-scheme',
                    'contention',
                ],
                {'mmap': 'tracepoint', 'cgroup': 'contention', 'fork': 'kprobe'},
            ),
        )
        for command, handler in (
            (['run'], 'lockbench.combined_run'),
            (['observer', 'run'], 'observer.cli.observer_run'),
            (['bench', 'run', '--workload', 'mmap'], 'bench.cli.bench_run'),
        ):
            for flags, expected in cases:
                with self.subTest(command=command, flags=flags), patch(
                    handler, return_value=0
                ) as run_command:
                    lockbench.main(command + ['--target', 'all'] + flags)
                    selections = resolve(run_command.call_args.args[0])
                    self.assertEqual(
                        {item.backend.target: item.backend.method for item in selections}, expected
                    )
            for flags, valid in (([], False), (['--mmap-scheme', 'fentry'], True)):
                with self.subTest(command=command, timer=True, flags=flags), patch(
                    handler, return_value=0
                ) as run_command:
                    lockbench.main(
                        command
                        + [
                            '--target',
                            'all',
                            '--collect',
                            'state',
                            '--timeout',
                            'timer',
                            '--fork-timeout',
                            'poll',
                        ]
                        + flags
                    )
                    args = run_command.call_args.args[0]
                    if valid:
                        resolve(args)
                    else:
                        with self.assertRaisesRegex(ValueError, 'mmap/tracepoint has no timer'):
                            resolve(args)

    def test_slow_lock_defaults_and_explicit_count_mode(self):
        import lockbench
        from observer.catalog import resolve

        for command, handler in (
            (['run'], 'lockbench.combined_run'),
            (['observer', 'run'], 'observer.cli.observer_run'),
            (['bench', 'run', '--workload', 'mmap'], 'bench.cli.bench_run'),
        ):
            cases = (
                ([], 'stack', 'poll', 100000000, 100),
                (['--collect', 'state'], 'state', 'poll', 100000000, 100),
                (['--collect', 'count', '--timeout', 'none'], 'count', 'none', 100000000, 100),
                (['--threshold-ns', '50000000', '--poll-ms', '10'], 'stack', 'poll', 50000000, 10),
            )
            for flags, collect, timeout, threshold, poll in cases:
                with self.subTest(command=command, flags=flags), patch(
                    handler, return_value=0
                ) as run_command:
                    self.assertEqual(lockbench.main(command + ['--target', 'all'] + flags), 0)
                    selections = resolve(run_command.call_args.args[0])
                    self.assertEqual(len(selections), 3)
                    for item in selections:
                        self.assertEqual(item.collect, collect)
                        self.assertEqual(item.timeout, timeout)
                        self.assertEqual(item.threshold_ns, threshold)
                        self.assertEqual(item.poll_ms, poll)

    def test_collectors_are_peers_and_all_stopped_on_error(self):
        calls = []

        class Fake:
            def __init__(self, name, fail=False):
                self.name = name
                self.fail = fail

            def prepare(self):
                calls.append(self.name + ':prepare')

            def start(self):
                calls.append(self.name + ':start')

            def cpu_ns(self):
                return 0

            def stop(self):
                calls.append(self.name + ':stop')
                if self.fail:
                    raise RuntimeError('stop failed')

            def result(self):
                return {'name': self.name}

            def close(self):
                calls.append(self.name + ':close')

        result = run({'locks': Fake('locks'), 'system': Fake('system')}, 0.001)
        self.assertEqual(
            result['collectors'], {'locks': {'name': 'locks'}, 'system': {'name': 'system'}}
        )
        self.assertLess(calls.index('system:stop'), calls.index('locks:close'))
        calls.clear()
        with self.assertRaisesRegex(RuntimeError, 'stop failed'):
            run({'locks': Fake('locks'), 'system': Fake('system', True)}, 0.001)
        self.assertEqual(calls[-4:], ['system:stop', 'locks:stop', 'system:close', 'locks:close'])

    def test_system_only_checkout_needs_no_lock_collector(self):
        with tempfile.TemporaryDirectory() as name:
            folder = Path(name)
            for source in ('lockbench.py', 'cli.py', 'session.py', 'logutil.py'):
                shutil.copy2(ROOT / source, folder / source)
            shutil.copytree(
                ROOT / 'system', folder / 'system', ignore=shutil.ignore_patterns('__pycache__')
            )
            result = subprocess.run(
                [sys.executable, str(folder / 'lockbench.py'), 'system', 'run', '--help'],
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
            self.assertNotIn('observer', result.stdout)
            if sys.platform == 'linux':
                result = subprocess.run(
                    [
                        sys.executable,
                        str(folder / 'lockbench.py'),
                        'system',
                        'run',
                        '--duration',
                        '.1',
                    ],
                    cwd=folder,
                    text=True,
                    capture_output=True,
                    timeout=10,
                )
                self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()
