"""Add experiment summaries to the standalone report without embedding raw measurements."""

import base64
import html
import json
from pathlib import Path
import re

from analysis.lock_counts import count_text, rate_text
from workload.registry import ROOT

START = '<!-- LOCKBENCH_UNIFIED_RESULTS_START -->'
END = '<!-- LOCKBENCH_UNIFIED_RESULTS_END -->'


def compact_report(markup):
    """Keep published tables while removing legacy raw-data downloads."""
    markup = re.sub(r'<script\b[^>]*\bid="report-data"[^>]*>.*?</script>', '', markup, flags=re.S)
    markup = re.sub(
        r'<script\b[^>]*>(.*?)</script>',
        lambda match: '' if 'report-data' in match[1] else match[0],
        markup,
        flags=re.S,
    )
    return re.sub(r'<div\b[^>]*\bid="downloads"[^>]*>.*?</div>', '', markup, flags=re.S)


def report(inputs, output):
    if not inputs:
        inputs = sorted((ROOT / 'bench/experiments').glob('*/results/run-*/summary.json'))
    summaries = []
    for value in inputs:
        path = Path(value)
        path = path / 'summary.json' if path.is_dir() else path
        summary = json.loads(path.read_text(encoding='utf-8'))
        if summary.get('schema_version') != 1:
            raise ValueError('report requires unified bench summaries')
        summaries.append((path, summary))
    template = output if output.exists() else ROOT / 'docs/REPORT.html'
    markup = compact_report(template.read_text(encoding='utf-8'))
    markup = re.sub(re.escape(START) + r'.*?' + re.escape(END), '', markup, flags=re.S)
    rows, entry_rows = [], []

    def number(stats, key, signed=False):
        if key not in stats:
            return '—'
        return format(stats[key]['median'], '+.2f' if signed else '.2f')

    for path, summary in summaries:
        stats = summary['statistics']
        parameters_path = path.parent / 'parameters.json'
        parameters = (
            json.loads(parameters_path.read_text(encoding='utf-8'))
            if parameters_path.exists()
            else {}
        )
        observers = summary.get('observers', {})
        config = '; '.join(
            target
            + ': '
            + ' / '.join(str(item.get(key) or '—') for key in ('scheme', 'collect', 'timeout'))
            for target, item in observers.items()
        )
        if not config:
            config = ' / '.join(
                str(parameters.get(key, '—')) for key in ('target', 'scheme', 'collect', 'timeout')
            )
        payload = base64.b64encode(json.dumps(summary, ensure_ascii=False).encode()).decode()
        name = html.escape(summary['workload'])
        batch = html.escape(path.parent.name)
        stats_note = '—'
        if 'cpu_delta_ms' in stats:
            stats_note = f'{stats["cpu_delta_ms"]["madn"]:.2f}'
        host_events = sum(
            item['median'] for key, item in stats.items() if key.endswith('_match_start')
        )
        rows.append(
            f'<tr><td>{name}<small>{batch}</small></td><td>{html.escape(config)}</td><td>{summary["pairs"]}</td>'
            f'<td>{number(stats,"baseline_cpu_ms")}</td><td>{number(stats,"cpu_delta_ms",True)}<small>{number(stats,"cpu_delta_percent",True)}%</small></td>'
            f'<td>{stats_note}</td><td>{number(stats,"wall_delta_ms",True)}</td>'
            f'<td>{number(stats,"throughput_loss_percent",True)}</td><td>{host_events:,.0f}</td>'
            f'<td><a download="{name}-summary.json" href="data:application/json;base64,{payload}">JSON</a></td></tr>'
        )
        if summary.get('observed') is not False and (
            'mmap' in observers
            or parameters.get('target') in ('mmap', 'all')
            or any(key.startswith('mmap_') for key in stats)
        ):
            scheme = observers.get('mmap', {}).get('scheme') or parameters.get('scheme', '未记录')
            for direction, title in (('read', '读'), ('write', '写')):
                total = stats.get('mmap_total_' + direction + '_start', {}).get('median')
                matched = stats.get('mmap_match_' + direction + '_start', {}).get('median')
                rate = stats.get('mmap_' + direction + '_hit_percent', {}).get('median')
                entry_rows.append(
                    f'<tr><td>{name}<small>{batch}</small></td><td>{html.escape(str(scheme))}</td>'
                    f'<td>{title}</td><td>{count_text(total)}</td><td>{count_text(matched)}</td>'
                    f'<td>{rate_text(rate, total, matched)}</td></tr>'
                )
    section = (
        START
        + '''<section class="unified-bench" id="unified-bench-results">
<style>.unified-bench{font-family:system-ui,sans-serif;max-width:1440px;margin:28px auto;padding:0 20px;color:#172b4d}
.unified-bench table{border-collapse:collapse;width:100%;font-size:13px}.unified-bench th,.unified-bench td{padding:12px 9px;border-bottom:1px solid #dce3ec;text-align:right}
.unified-bench th:nth-child(-n+2),.unified-bench td:nth-child(-n+2){text-align:left}.unified-bench small{display:block;color:#6b7c93;font-size:11px;margin-top:4px}
.unified-bench .scroll{overflow:auto}.unified-bench h2{font-size:22px}.unified-bench p{font-size:13px;color:#52657b}</style>
<h2>统一实验框架结果</h2><p>各指标分别取配对轮次中位数。CPU 与墙钟单位 ms；吞吐损失单位 %；MADN 为 CPU 增量的波动。
事件次数属于整台主机，不能当作仅由负载触发。固定时长负载应结合吞吐损失，固定工作量负载结合 CPU 与墙钟增量。</p>
<div class="scroll"><table><thead><tr><th>负载 / 批次</th><th>对象 / 接入 / 采集 / 超时</th><th>轮次</th><th>无观测 CPU</th><th>增量 CPU</th><th>CPU 增量 MADN</th><th>增量墙钟</th><th>吞吐损失</th><th>整机事件</th><th>下载</th></tr></thead><tbody>'''
        + ''.join(rows)
        + '''</tbody></table></div>
<h3>mmap_lock 入口命中</h3>
<div class="scroll"><table><thead><tr><th>负载 / 批次</th><th>接入方式</th><th>方向</th><th>入口触发</th><th>mmap_lock 命中</th><th>命中率</th></tr></thead><tbody>'''
        + (''.join(entry_rows) or '<tr><td colspan="6">未采集 mmap_lock。</td></tr>')
        + '''</tbody></table></div>
<p>触发次数、命中次数分别取各轮中位数；命中率先按轮计算“命中÷触发”，再取中位数，不用两个中位数相除。
fentry/kprobe 触发包含其它 rwsem；tracepoint/raw 触发来自 mmap_lock 事件。命中为成功纳入跟踪的入口，不含降级。缺字段显示“未记录”；零触发或缺少完整有效轮次的比率显示 —。</p>
<p>下方保留原已发布批次；其负载、采集实现及 CPU 范围按原报告解释。</p></section>'''
        + END
    )
    if '<body' in markup:
        markup = re.sub(r'(<body\b[^>]*>)', lambda match: match[1] + section, markup, count=1)
    else:
        markup = '<!doctype html><html><meta charset="utf-8"><body>' + section + '</body></html>'
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(markup, encoding='utf-8')
    print(f'REPORT: {output}; {len(summaries)} unified batches')
    return 0
