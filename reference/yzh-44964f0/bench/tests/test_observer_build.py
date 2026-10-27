from pathlib import Path
import contextlib
import io
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import lockbench
from observer.build import compiler, prepare_header


class ObserverBuildTests(unittest.TestCase):
    def test_native_compiler_falls_back_to_cc_then_clang(self):
        for available in ('cc', 'clang'):
            with self.subTest(available=available), patch.dict('os.environ', {}, clear=True), patch(
                'observer.build.shutil.which',
                side_effect=lambda name: '/tools/' + name if name == available else None,
            ):
                self.assertEqual(compiler('CC', ('gcc', 'cc', 'clang')), '/tools/' + available)

    def test_explicit_compiler_is_used_and_invalid_override_fails(self):
        with patch.dict('os.environ', {'CC': '/tools/custom-cc'}, clear=True), patch(
            'observer.build.shutil.which', return_value='/tools/custom-cc'
        ) as which:
            self.assertEqual(compiler('CC', ('gcc', 'cc', 'clang')), '/tools/custom-cc')
            which.assert_called_once_with('/tools/custom-cc')
        with patch.dict('os.environ', {'CC': 'absent-cc'}, clear=True), patch(
            'observer.build.shutil.which', return_value=None
        ):
            with self.assertRaisesRegex(ValueError, 'CC compiler not found: absent-cc'):
                compiler('CC', ('gcc', 'cc', 'clang'))

    def test_missing_compilers_have_actionable_errors(self):
        with patch.dict('os.environ', {}, clear=True), patch(
            'observer.build.shutil.which', return_value=None
        ):
            for variable, candidates in [('CC', ('gcc', 'cc', 'clang')), ('CLANG', ('clang',))]:
                with self.assertRaisesRegex(ValueError, f'set {variable}'):
                    compiler(variable, candidates)

    def test_supplied_header_needs_no_btf_reader_or_external_tool(self):
        with tempfile.TemporaryDirectory() as name:
            folder = Path(name)
            output = folder / 'build'
            output.mkdir()
            source = folder / 'custom.h'
            source.write_text('struct task_struct { int pid; };\n')
            with patch('observer.build.subprocess.run') as run:
                prepare_header(output, source, folder / 'no-kernel-btf')
            run.assert_not_called()
            self.assertEqual((output / 'vmlinux.h').read_bytes(), source.read_bytes())
            self.assertFalse((output / 'vmlinux.h.tmp').exists())

    def test_failed_export_retains_previous_header(self):
        with tempfile.TemporaryDirectory() as name:
            folder = Path(name)
            btf = folder / 'kernel.btf'
            btf.write_bytes(b'fixture')
            header = folder / 'vmlinux.h'
            header.write_text('previous header')
            calls = []

            def command(args, **kwargs):
                calls.append(args)
                if 'stdout' in kwargs:
                    kwargs['stdout'].write(b'incomplete export')
                    raise subprocess.CalledProcessError(1, args)

            with patch('observer.build.subprocess.run', side_effect=command), patch(
                'observer.build.compiler', return_value='/tools/cc'
            ):
                with self.assertRaises(subprocess.CalledProcessError):
                    prepare_header(folder, btf_path=btf)
            self.assertEqual(header.read_text(), 'previous header')
            self.assertFalse((folder / 'vmlinux.h.tmp').exists())
            self.assertEqual(len(calls), 2)
            self.assertFalse(any('bpftool' in str(part) for call in calls for part in call))

    def test_missing_btf_and_empty_header_have_clear_errors(self):
        with tempfile.TemporaryDirectory() as name:
            folder = Path(name)
            empty = folder / 'empty.h'
            empty.write_text('')
            with self.assertRaisesRegex(ValueError, 'nonempty C header'):
                prepare_header(folder, empty)
            with self.assertRaisesRegex(ValueError, '--vmlinux-header'):
                prepare_header(folder, btf_path=folder / 'absent')

    def test_public_build_commands_pass_header_but_inspect_rejects_it(self):
        for command in (['observer', 'build'], ['bench', 'build', '--workload', 'mmap']):
            with self.subTest(command=command), patch(
                'observer.build.build', return_value=0
            ) as build, patch('bench.cli.workload_build', return_value=0):
                self.assertEqual(
                    lockbench.main(
                        command
                        + [
                            '--target',
                            'mmap',
                            '--scheme',
                            'tracepoint',
                            '--vmlinux-header',
                            'custom.h',
                        ]
                    ),
                    0,
                )
                products, header = build.call_args.args
                self.assertEqual([p.id for p in products], ['mmap/tracepoint'])
                self.assertEqual(header, Path('custom.h').resolve())
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
            lockbench.main(['observer', 'inspect', '--vmlinux-header', 'custom.h'])
        self.assertEqual(error.exception.code, 2)


if __name__ == '__main__':
    unittest.main()
