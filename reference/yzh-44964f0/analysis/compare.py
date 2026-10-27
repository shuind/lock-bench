"""Read exported files and render a self-contained on/off comparison."""

from collections import Counter
from datetime import datetime, timedelta, timezone
import html
import json
import math
from pathlib import Path
import re

from .lock_counts import count_text, mmap_entry_counts, rate_text


GIB = 1024**3
CPU_FIELDS = ('user', 'nice', 'system', 'idle', 'iowait', 'irq', 'softirq', 'steal')
ERROR_COUNTERS = (
    'state_errors',
    'stack_errors',
    'pair_errors',
    'timer_errors',
    'ring_dropped',
)
METRICS = (
    ('cpu', 'CPU 平均利用率', '%', 'pp'),
    ('cpu_peak', 'CPU 采样峰值', '%', 'pp'),
    ('iowait', 'I/O wait 平均比例', '%', 'pp'),
    ('memory', '内存平均占用', 'GiB', 'value'),
    ('memory_peak', '内存采样峰值', 'GiB', 'value'),
    ('load', '平均 1 分钟系统负载', '', 'value'),
    ('psi_cpu', 'CPU PSI some 停顿比例', '%', 'pp'),
    ('psi_memory', '内存 PSI some 停顿比例', '%', 'pp'),
    ('psi_io', 'I/O PSI some 停顿比例', '%', 'pp'),
)


def number(value):
    return (
        value
        if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)
        else None
    )


def get(value, *keys):
    for key in keys:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


def read_json(path):
    try:
        value = json.loads(Path(path).read_text(encoding='utf-8-sig'))
    except json.JSONDecodeError as exc:
        raise ValueError(f'{path}: JSON 无效或尚未写完，请等待观测结束：{exc}') from exc
    if not isinstance(value, dict):
        raise ValueError(f'{path}: 应为观测结果 JSON 对象')
    return value


def cpu_parts(before, after):
    old, new = get(before, 'cpu', 'ticks'), get(after, 'cpu', 'ticks')
    if not isinstance(old, dict) or not isinstance(new, dict):
        return None
    if any(number(old.get(k)) is None or number(new.get(k)) is None for k in CPU_FIELDS):
        return None
    delta = {k: new[k] - old[k] for k in CPU_FIELDS}
    total = sum(delta.values())
    if total <= 0 or min(delta.values()) < 0:
        return None
    return (total - delta['idle'] - delta['iowait'], delta['iowait'], total)


def pressure(before, after, resource, dt):
    old = number(get(before, 'psi', resource, 'some', 'total_us'))
    new = number(get(after, 'psi', resource, 'some', 'total_us'))
    if old is not None and new is not None:
        return (new - old) * 100000 / dt if new >= old else None
    return number(get(after, 'psi', resource, 'some', 'interval_percent'))


def lock_objects(locks):
    if not isinstance(locks, dict):
        return {}
    if isinstance(locks.get('objects'), dict):
        return locks['objects']
    return {locks.get('target', 'unknown'): locks}


def load_run(path, series_path=None, expected=None):
    path = Path(path)
    value = read_json(path)
    collectors = value.get('collectors', {})
    system = collectors.get('system', {}) if isinstance(collectors, dict) else {}
    if 'samples' in value:
        system = value
    locks = collectors.get('locks') if isinstance(collectors, dict) else None
    if locks is None and ('objects' in value or 'counters' in value):
        locks = value
    if locks is not None and expected is not None:
        for item in lock_objects(locks).values():
            if not isinstance(item, dict) or item.get('observe') is not expected:
                raise ValueError(f'{path}: --on 应为 observe=on，--off 应为 observe=off')
    warnings = []
    if series_path:
        samples = []
        with Path(series_path).open(encoding='utf-8-sig') as stream:
            for line_number, line in enumerate(stream, 1):
                if not line.strip():
                    continue
                try:
                    samples.append(json.loads(line))
                except json.JSONDecodeError as exc:
                    raise ValueError(f'{series_path}:{line_number}: 系统采样 JSON 无效') from exc
    else:
        samples = system.get('samples', [])
        if system.get('samples_truncated'):
            warnings.append(
                '最终 JSON 的采样已截断；当前汇总和曲线仅覆盖保留窗口。请提供对应的完整系统 JSONL。'
            )
    if not isinstance(samples, list) or len(samples) < 2:
        raise ValueError(
            f'{path}: 至少需要两个系统样本；请提供对应的 --on-system / --off-system JSONL'
        )
    times = [number(get(s, 'monotonic_ns')) for s in samples]
    if any(t is None or t < 0 for t in times) or any(b <= a for a, b in zip(times, times[1:])):
        raise ValueError(f'{path}: 系统样本的 monotonic_ns 必须严格递增')
    if series_path:
        for key, actual in (('start_ns', times[0]), ('end_ns', times[-1])):
            if number(system.get(key)) is not None and system[key] != actual:
                raise ValueError(f'{series_path}: 时间边界与 {path.name} 不符，可能选错采样文件')
        if system.get('samples_total') and system['samples_total'] != len(samples):
            warnings.append('系统 JSONL 的记录数与最终 JSON 不符，可能有采样缺失。')
    errors = Counter()
    for sample in samples:
        for source, reason in (sample.get('errors') or {}).items():
            errors[f'{source}: {reason}'] += 1
    for reason, count in errors.items():
        warnings.append(f'指标读取失败（{count} 个样本）：{reason}')
    for key, reason in (system.get('errors') or {}).items():
        warnings.append(f'系统采集异常 {key}: {reason}')
    cpus = {
        get(s, 'cpu', 'logical_cpus')
        for s in samples
        if number(get(s, 'cpu', 'logical_cpus')) is not None
    }
    if len(cpus) > 1:
        warnings.append('采样期间在线逻辑 CPU 数发生变化。')
    duration = (times[-1] - times[0]) / 1e9
    nominal = number(system.get('interval_ms'))
    gaps = [b - a for a, b in zip(times, times[1:])]
    if nominal and max(gaps) > nominal * 5e6:
        warnings.append(f'最大采样间隔 {max(gaps)/1e9:.2f} 秒；瞬时峰值可能遗漏。')
    return dict(
        path=str(path),
        system=system,
        samples=samples,
        locks=locks,
        warnings=warnings,
        duration=duration,
        cpus=sorted(cpus),
        series_path=str(series_path) if series_path else None,
    )


def summarize(run):
    samples = run['samples']
    weighted = Counter()
    weights = Counter()
    busy_ticks = wait_ticks = all_ticks = 0
    cpu_values = []
    points = []
    invalid_cpu = 0
    for index, sample in enumerate(samples):
        point = dict(
            t=(sample['monotonic_ns'] - samples[0]['monotonic_ns']) / 1e9,
            memory=number(get(sample, 'memory', 'used_bytes')),
            load=number(get(sample, 'load', 'load1')),
            cpu=None,
            psi_cpu=None,
            psi_memory=None,
            psi_io=None,
        )
        if point['memory'] is not None:
            point['memory'] /= GIB
        if index:
            previous = samples[index - 1]
            dt = sample['monotonic_ns'] - previous['monotonic_ns']
            parts = cpu_parts(previous, sample)
            if parts:
                busy, wait, total = parts
                busy_ticks += busy
                wait_ticks += wait
                all_ticks += total
                point['cpu'] = 100 * busy / total
            else:
                invalid_cpu += 1
            if point['cpu'] is not None:
                cpu_values.append(point['cpu'])
            for key, source in (('memory', ('memory', 'used_bytes')), ('load', ('load', 'load1'))):
                current = number(get(previous, *source))
                if current is not None:
                    weighted[key] += current * dt
                    weights[key] += dt
            for resource in ('cpu', 'memory', 'io'):
                key = 'psi_' + resource
                point[key] = pressure(previous, sample, resource, dt)
                if point[key] is not None:
                    weighted[key] += point[key] * dt
                    weights[key] += dt
        points.append(point)
    stats = {
        key: weighted[key] / weights[key] if weights[key] else None
        for key in ('memory', 'load', 'psi_cpu', 'psi_memory', 'psi_io')
    }
    if stats['memory'] is not None:
        stats['memory'] /= GIB
    stats.update(
        cpu=100 * busy_ticks / all_ticks if all_ticks else None,
        iowait=100 * wait_ticks / all_ticks if all_ticks else None,
        cpu_peak=max(cpu_values, default=None),
        memory_peak=max((p['memory'] for p in points if p['memory'] is not None), default=None),
    )
    if invalid_cpu:
        run['warnings'].append(f'{invalid_cpu} 个区间 CPU 计数不可用或回退，未计入 CPU 汇总。')
    run.update(stats=stats, points=points)
    return run


def escape(value):
    return html.escape(str(value), quote=True)


def display(value, signed=False):
    return '不可用' if number(value) is None else format(value, '+.2f' if signed else '.2f')


def stamp(sample):
    value = number(sample.get('wall_time_ns'))
    if value is None:
        return '未记录时间'
    return datetime.fromtimestamp(value / 1e9, timezone(timedelta(hours=8))).strftime(
        '%Y-%m-%d %H:%M:%S'
    )


def lock_sections(run, label):
    rows, events, notes = [], [], []
    objects = lock_objects(run['locks'])
    if not objects:
        return '', f'<li>{label}：未提供锁采集结果。</li>', ''
    for target, item in objects.items():
        counters = item.get('counters', {})
        failures = {k: v for k, v in counters.items() if k in ERROR_COUNTERS and v}
        failures.update(
            {
                k: item[k]
                for k in (
                    'error',
                    'cleanup_error',
                    'live_poll_errors',
                    'retprobe_misses',
                    'mmap_cleanup_errors',
                )
                if item.get(k)
            }
        )
        errors = '；'.join(f'{k}={v}' for k, v in failures.items()) or '未报告错误'
        if failures:
            notes.append(f'<li>{label} / {escape(target)}：{escape(errors)}</li>')
        starts = counters.get('match_start')
        starts_text = f'{starts:,}' if isinstance(starts, int) else '未记录'
        config = ' / '.join(str(item.get(k, '—')) for k in ('scheme', 'collect', 'timeout'))
        threshold = number(item.get('threshold_ns'))
        config += f' / {threshold/1e6:g} ms' if threshold is not None else ''
        reports = item.get('live_reports')
        reports_text = str(reports) if isinstance(reports, int) else '未记录'
        if item.get('observe') is False:
            starts_text = reports_text = '未采集'
            config = '未启用（不挂载探针）'
        rows.append(
            f'<tr><td>{label}</td><td>{escape(target)}</td><td>{escape(config)}</td><td>{starts_text}</td><td>{reports_text}</td><td>{escape(errors)}</td></tr>'
        )
        stacks = {s.get('id'): s.get('ips', []) for s in item.get('entry_stacks', [])}
        for event in sorted(
            item.get('live_events', []), key=lambda e: number(e.get('age_ns')) or 0, reverse=True
        )[:8]:
            stage = (
                'fork 阶段'
                if target == 'fork'
                else '获取中' if event.get('stage') == 1 else '已获取'
            )
            kind = (
                '写'
                if event.get('lock_kind') == 2
                else '读' if event.get('lock_kind') == 1 else '阶段'
            )
            stack = stacks.get(event.get('stack_id'))
            content = (
                '\n'.join(str(ip) for ip in stack)
                if stack
                else '该入口栈未包含在最终 JSON 中；请查看原 observer.log。'
            )
            age = number(event.get('age_ns'))
            age = display(age / 1e6 if age is not None else None)
            events.append(
                f'<details><summary>{label} · {escape(target)} · PID {escape(event.get("tgid"))} / TID {escape(event.get("tid"))} · {kind} / {stage} · {age} ms</summary><p>锁地址：<code>{escape(event.get("lock_addr", "—"))}</code> · 入口栈 ID：{escape(event.get("stack_id"))}</p><pre>{escape(content)}</pre></details>'
            )
        if item.get('live_events_truncated'):
            notes.append(
                f'<li>{label} / {escape(target)}：导出的慢提示明细已截断；累计提示数仍取 live_reports。</li>'
            )
        if item.get('unfinished_truncated') or item.get('state_entries'):
            notes.append(
                f'<li>{label} / {escape(target)}：停止时仍有未完成状态，不能据此认定死锁。</li>'
            )
    return ''.join(rows), ''.join(notes), ''.join(events)


def mmap_entry_rows(run, label):
    rows = []
    for target, item in lock_objects(run['locks']).items():
        if target != 'mmap' or item.get('observe') is False:
            continue
        counts = mmap_entry_counts(item.get('counters', {}))
        for direction, title in (('read', '读'), ('write', '写')):
            total = counts['total_' + direction + '_start']
            matched = counts['match_' + direction + '_start']
            rate = counts[direction + '_hit_percent']
            rows.append(
                f'<tr><td>{escape(label)}</td><td>{escape(item.get("scheme", "未记录"))}</td>'
                f'<td>{title}</td><td>{count_text(total)}</td><td>{count_text(matched)}</td>'
                f'<td>{rate_text(rate, total, matched)}</td></tr>'
            )
    return ''.join(rows)


def write_report(on_path, off_path, output, on_system=None, off_system=None):
    on = summarize(load_run(on_path, on_system, True))
    off = summarize(load_run(off_path, off_system, False))
    paths = [Path(p).resolve() for p in (on_path, off_path, on_system, off_system) if p]
    output = Path(output)
    if output.resolve() in paths:
        raise ValueError('报告输出路径不能覆盖输入文件')
    rows = []
    for key, title, unit, kind in METRICS:
        a, b = on['stats'][key], off['stats'][key]
        delta = a - b if a is not None and b is not None else None
        suffix = ' 个百分点' if kind == 'pp' else (' ' + unit if unit else '')
        rows.append(
            f'<tr><th>{title}<small>{unit}</small></th><td>{display(b)}</td><td>{display(a)}</td><td>{display(delta,True)}{suffix if delta is not None else ""}</td></tr>'
        )
    notes = []
    cards = []
    lock_rows, slow_events, mmap_rows = [], [], []
    for run, label in ((off, '关闭观测'), (on, '开启观测')):
        cards.append(
            f'<article><h2>{label}</h2><strong>{run["duration"]/60:.2f}<small>分钟</small></strong><p>{stamp(run["samples"][0])} — {stamp(run["samples"][-1])}</p><p>{len(run["samples"]):,} 次采样 · 逻辑 CPU：{escape(", ".join(map(str,run["cpus"])) or "未记录")}</p><code>{escape(Path(run["path"]).name)}</code></article>'
        )
        notes.extend(f'<li>{label}：{escape(note)}</li>' for note in run['warnings'])
        r, n, e = lock_sections(run, label)
        lock_rows.append(r)
        notes.append(n)
        slow_events.append(e)
        mmap_rows.append(mmap_entry_rows(run, label))
    if abs(on['duration'] - off['duration']) / max(on['duration'], off['duration']) > 0.05:
        notes.append('<li>两轮采样窗口时长相差超过 5%，请确认是否完成了预定对照。</li>')
    if on['cpus'] != off['cpus']:
        notes.append('<li>两轮逻辑 CPU 数不同，CPU 比例和系统负载不宜直接比较。</li>')
    data = json.dumps(
        dict(on=on['points'], off=off['points']),
        ensure_ascii=False,
        allow_nan=False,
        separators=(',', ':'),
    ).replace('<', '\\u003c')
    markup = Path(__file__).with_name('comparison.html').read_text(encoding='utf-8')
    replacements = dict(
        CARDS=''.join(cards),
        ROWS=''.join(rows),
        NOTES=''.join(notes)
        or '<li>输入文件未报告采样或采集错误。</li>',
        LOCK_ROWS=''.join(lock_rows),
        MMAP_ROWS=''.join(mmap_rows)
        or '<tr><td colspan="6">未采集 mmap_lock。</td></tr>',
        EVENTS=''.join(slow_events) or '<p>最终 JSON 中没有可展示的慢提示明细。</p>',
        DATA=data,
    )
    markup = re.sub(r'@@([A-Z_]+)@@', lambda match: replacements[match[1]], markup)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(markup, encoding='utf-8')
    print(f'COMPARE: {output}; off={len(off["samples"])} samples, on={len(on["samples"])} samples')
    return dict(on=on, off=off)
