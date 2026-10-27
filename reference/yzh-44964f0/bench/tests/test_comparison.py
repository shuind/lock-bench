import contextlib
import io
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

from analysis.compare import load_run, mmap_entry_rows, summarize, write_report

ROOT = Path(__file__).resolve().parents[2]


def samples():
    rows = []
    for seconds, user, idle, memory, load, pressure in (
        (0, 0, 0, 1, 2, 0),
        (1, 20, 80, 3, 4, 100000),
        (4, 200, 200, 5, 6, 1000000),
    ):
        ticks = dict.fromkeys(
            ('user', 'nice', 'system', 'idle', 'iowait', 'irq', 'softirq', 'steal'), 0
        )
        ticks.update(user=user, idle=idle)
        rows.append(
            dict(
                monotonic_ns=seconds * 10**9,
                wall_time_ns=1700000000000000000 + seconds * 10**9,
                cpu=dict(ticks=ticks, logical_cpus=2),
                memory=dict(used_bytes=memory * 1024**3),
                load=dict(load1=load),
                psi=dict(cpu=dict(some=dict(total_us=pressure)), memory=None, io=None),
                errors={},
            )
        )
    return rows


def session(path, observe, truncate=False):
    rows = samples()
    system = dict(
        start_ns=0,
        end_ns=4 * 10**9,
        samples_total=3,
        samples_truncated=truncate,
        samples=rows[1:] if truncate else rows,
        errors={},
        interval_ms=1000,
    )
    locks = dict(
        target='mmap',
        observe=observe,
        scheme='tracepoint',
        collect='stack',
        timeout='poll',
        threshold_ns=100000000,
        live_reports=300 if observe else 0,
        live_events_truncated=observe,
        counters=dict(
            match_start=100 if observe else 0,
            total_read_start=1000 if observe else 0,
            match_read_start=25 if observe else 0,
            total_write_start=300 if observe else 0,
            match_write_start=75 if observe else 0,
            stack_errors=1 if observe else 0,
        ),
        live_events=(
            [
                dict(
                    tgid=123,
                    tid=124,
                    stage=1,
                    age_ns=150000000,
                    stack_id=7,
                    lock_kind=1,
                    lock_addr='0xffffffffffffffff',
                )
            ]
            if observe
            else []
        ),
        entry_stacks=[dict(id=7, ips=['0xfffffffffffffffe'])] if observe else [],
    )
    path.write_text(json.dumps(dict(collectors=dict(system=system, locks=locks))), encoding='utf-8')
    return rows


class ComparisonTests(unittest.TestCase):
    def test_weighted_metrics_missing_pressure_and_truncation(self):
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / 'on.json'
            rows = session(path, True, truncate=True)
            limited = summarize(load_run(path, expected=True))
            self.assertTrue(any('截断' in text for text in limited['warnings']))
            series = Path(name) / 'system.jsonl'
            series.write_text(''.join(json.dumps(row) + '\n' for row in rows), encoding='utf-8')
            run = summarize(load_run(path, series, True))
            self.assertEqual(run['stats']['cpu'], 50)
            self.assertEqual(run['stats']['cpu_peak'], 60)
            self.assertEqual(run['stats']['memory'], 2.5)
            self.assertEqual(run['stats']['memory_peak'], 5)
            self.assertEqual(run['stats']['load'], 3.5)
            self.assertEqual(run['stats']['psi_cpu'], 25)
            self.assertIsNone(run['stats']['psi_memory'])
            self.assertEqual(run['points'][0]['psi_cpu'], None)
            self.assertFalse(any('截断' in text for text in run['warnings']))

    def test_swapped_roles_wrong_series_and_incomplete_results_rejected(self):
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / 'on.json'
            rows = session(path, True)
            with self.assertRaisesRegex(ValueError, 'observe=on'):
                load_run(path, expected=False)
            series = Path(name) / 'wrong.jsonl'
            series.write_text(''.join(json.dumps(row) + '\n' for row in rows[1:]), encoding='utf-8')
            with self.assertRaisesRegex(ValueError, '时间边界'):
                load_run(path, series, True)
            path.write_text('', encoding='utf-8')
            with self.assertRaisesRegex(ValueError, '尚未写完'):
                load_run(path)

    def test_reset_counters_are_not_fake_zero(self):
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / 'on.json'
            session(path, True)
            data = json.loads(path.read_text())
            rows = data['collectors']['system']['samples']
            rows[0]['cpu']['ticks']['user'] = 1000
            rows[2]['cpu']['ticks']['idle'] = 0
            path.write_text(json.dumps(data))
            run = summarize(load_run(path))
            self.assertIsNone(run['stats']['cpu'])
            self.assertTrue(any('CPU 计数不可用' in note for note in run['warnings']))

    def test_report_is_offline_and_preserves_stack_addresses_and_error_notes(self):
        with tempfile.TemporaryDirectory() as name:
            folder = Path(name)
            on = folder / 'on.json'
            off = folder / 'off.json'
            session(on, True)
            session(off, False)
            value = json.loads(on.read_text())
            value['collectors']['locks']['live_events'][0][
                'lock_addr'
            ] = '</script><script>alert(1)</script>'
            on.write_text(json.dumps(value))
            destination = folder / 'report.html'
            with contextlib.redirect_stdout(io.StringIO()):
                write_report(on, off, destination)
            text = destination.read_text(encoding='utf-8')
            self.assertIn('stack_errors=1', text)
            self.assertIn('累计提示数仍取 live_reports', text)
            self.assertIn('0xfffffffffffffffe', text)
            self.assertIn('&lt;/script&gt;', text)
            self.assertNotIn('<script>alert(1)</script>', text)
            self.assertIn('个百分点', text)
            self.assertIn('未采集', text)
            self.assertIn('<td>读</td><td>1,000</td><td>25</td><td>2.50%</td>', text)
            self.assertIn('<td>写</td><td>300</td><td>75</td><td>25.00%</td>', text)
            self.assertNotIn('@@', text)
            data = json.loads(
                re.search(
                    r'<script id="chart-data" type="application/json">(.*?)</script>', text, re.S
                )[1]
            )
            self.assertEqual(
                set(data['on'][0]),
                {'t', 'cpu', 'memory', 'load', 'psi_cpu', 'psi_memory', 'psi_io'},
            )
            self.assertNotIn('https://', text)
            with self.assertRaisesRegex(ValueError, '不能覆盖'):
                write_report(on, off, on)

    def test_mmap_entry_counts_distinguish_missing_zero_and_disabled(self):
        item = dict(target='mmap', scheme='kprobe', observe=True, counters={})
        run = dict(locks=item)
        self.assertIn('<td>读</td><td>未记录</td><td>未记录</td><td>未记录</td>', mmap_entry_rows(run, 'on'))
        item['counters'].update(total_read_start=0, match_read_start=0)
        self.assertIn('<td>读</td><td>0</td><td>0</td><td>—</td>', mmap_entry_rows(run, 'on'))
        item['counters'].update(total_read_start=1000, match_read_start=0)
        self.assertIn('<td>读</td><td>1,000</td><td>0</td><td>0.00%</td>', mmap_entry_rows(run, 'on'))
        item['observe'] = False
        self.assertEqual(mmap_entry_rows(run, 'off'), '')

    @unittest.skipUnless(shutil.which('node'), 'Node.js required only for chart script checks')
    def test_chart_script_switches_metrics_and_handles_missing_values(self):
        with tempfile.TemporaryDirectory() as name:
            folder = Path(name)
            on, off = folder / 'on.json', folder / 'off.json'
            session(on, True)
            session(off, False)
            output = folder / 'comparison.html'
            with contextlib.redirect_stdout(io.StringIO()):
                write_report(on, off, output)
            script = r'''
const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
const markup=fs.readFileSync(process.argv[2],'utf8');
const data=markup.match(/<script id="chart-data" type="application\/json">([\s\S]*?)<\/script>/)[1];
const code=[...markup.matchAll(/<script(?: [^>]*)?>([\s\S]*?)<\/script>/g)].at(-1)[1];
const nodes=new Map();
function element(){return {attrs:{},children:[],listeners:{},style:{},checked:true,value:'cpu',
 setAttribute(k,v){this.attrs[k]=v;if(k==='id')nodes.set(v,this);},
 appendChild(e){this.children.push(e);},replaceChildren(){this.children=[];},
 addEventListener(k,fn){this.listeners[k]=fn;},getBoundingClientRect(){return {left:0,width:1080};}};}
['chart-data','chart','tip','metric','show-on','show-off'].forEach(id=>nodes.set(id,element()));
nodes.get('chart-data').textContent=data;
const document={getElementById:id=>nodes.get(id),createElementNS:()=>element()};
vm.runInNewContext(code,{document});
const chart=nodes.get('chart'),metric=nodes.get('metric');
const paths=()=>chart.children.filter(x=>'d' in x.attrs);
assert.equal(paths().length,2);assert(paths().every(x=>!x.attrs.d.includes('NaN')));
chart.listeners.mousemove({clientX:300});assert(nodes.get('tip').textContent.includes('关闭观测'));
metric.value='memory';metric.listeners.change();assert.equal(paths().length,2);
metric.value='psi_memory';metric.listeners.change();
assert(paths().every(x=>x.attrs.d===''));assert(chart.children.some(x=>x.textContent==='该指标没有有效采样'));
['show-on','show-off'].forEach(id=>nodes.get(id).checked=false);
nodes.get('show-off').listeners.change();assert.equal(paths().length,0);
console.log('CHART_SCRIPT_PASS');
'''
            result = subprocess.run(
                [shutil.which('node'), '-', str(output)],
                input=script,
                capture_output=True,
                encoding='utf-8',
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('CHART_SCRIPT_PASS', result.stdout)

    def test_comparison_only_checkout_needs_no_collectors_or_workloads(self):
        with tempfile.TemporaryDirectory() as name:
            folder = Path(name)
            for source in ('lockbench.py', 'cli.py', 'logutil.py'):
                shutil.copy2(ROOT / source, folder / source)
            shutil.copytree(
                ROOT / 'analysis', folder / 'analysis', ignore=shutil.ignore_patterns('__pycache__')
            )
            on = folder / 'on.json'
            off = folder / 'off.json'
            session(on, True)
            session(off, False)
            output = folder / 'comparison.html'
            result = subprocess.run(
                [
                    sys.executable,
                    str(folder / 'lockbench.py'),
                    'compare',
                    '--on',
                    str(on),
                    '--off',
                    str(off),
                    '--output',
                    str(output),
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(output.is_file())
            help_text = subprocess.check_output(
                [sys.executable, str(folder / 'lockbench.py'), '--help'], text=True
            )
            self.assertIn('compare', help_text)
            self.assertNotIn('observer', help_text)


if __name__ == '__main__':
    unittest.main()
