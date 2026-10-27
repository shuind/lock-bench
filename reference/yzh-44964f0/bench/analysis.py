import csv
import json
from pathlib import Path
import statistics

from analysis.lock_counts import mmap_entry_counts


def describe(values):
    median = statistics.median(values)
    mad = statistics.median(abs(x - median) for x in values)
    return dict(
        median=median,
        mad=mad,
        madn=mad / 0.6744897501960817,
        min=min(values),
        max=max(values),
        rounds=values,
    )


def analyze(folder, write=True):
    folder = Path(folder)
    rows = [
        json.loads(line)
        for line in (folder / 'raw.jsonl').read_text(encoding='utf-8').splitlines()
        if line.strip()
    ]
    if not rows or any(row.get('schema_version') != 1 for row in rows):
        raise ValueError('analyze requires results from the unified bench runner')
    groups = {}
    for row in rows:
        side = 'probe' if row['observe'] else 'baseline'
        pair = groups.setdefault(row['repeat'], {})
        if side in pair:
            raise ValueError('Duplicate experiment arm')
        pair[side] = row
    parameters = json.loads((folder / 'parameters.json').read_text(encoding='utf-8'))
    if len(groups) != parameters['repeats']:
        raise ValueError('Experiment repeat count is incomplete')
    if parameters['observe'] == 'on' and any(
        set(arms) != {'baseline', 'probe'} for arms in groups.values()
    ):
        raise ValueError('An observed arm is missing from a pair')
    pairs = []
    observers = None
    for repeat, arms in sorted(groups.items()):
        if 'baseline' not in arms:
            raise ValueError('Missing paired baseline')
        a = arms['baseline']
        b = arms.get('probe')
        row = dict(
            repeat=repeat,
            baseline_operations=a['result']['operations'],
            unit=a['result']['unit'],
            baseline_cpu_ms=a['workload_cpu_ns'] / 1e6,
            baseline_wall_ms=a['wall_ns'] / 1e6,
            baseline_rate=a['result']['operations'] / (a['result']['wall_ns'] / 1e9),
        )
        if b:
            if (
                a['workload'] != b['workload']
                or a['cpu_scope'] != b['cpu_scope']
                or a['result']['unit'] != b['result']['unit']
            ):
                raise ValueError('Paired arms have incompatible scopes')
            row.update(
                probe_operations=b['result']['operations'],
                probe_cpu_ms=b['workload_cpu_ns'] / 1e6,
                probe_wall_ms=b['wall_ns'] / 1e6,
                observer_cpu_ms=b['observer_cpu_ns'] / 1e6,
                controller_cpu_ms=b['controller_cpu_ns'] / 1e6,
                probe_rate=b['result']['operations'] / (b['result']['wall_ns'] / 1e9),
            )
            row.update(
                cpu_delta_ms=row['probe_cpu_ms'] - row['baseline_cpu_ms'],
                wall_delta_ms=row['probe_wall_ms'] - row['baseline_wall_ms'],
                cpu_delta_percent=100 * (row['probe_cpu_ms'] / row['baseline_cpu_ms'] - 1),
                throughput_loss_percent=100 * (1 - row['probe_rate'] / row['baseline_rate']),
            )
            observation = b['observation']
            objects = observation.get('objects', {'one': observation})
            configuration = {
                item['target']: {
                    key: item.get(key) for key in ('scheme', 'collect', 'timeout', 'rw')
                }
                for item in objects.values()
            }
            if observers is not None and observers != configuration:
                raise ValueError('Observer configuration changed across pairs')
            observers = configuration
            for item in objects.values():
                for key in (
                    'total_start',
                    'match_start',
                    'match_read_start',
                    'match_write_start',
                    'match_downgrade',
                ):
                    row[item['target'] + '_' + key] = item['counters'].get(key)
                if item['target'] == 'mmap':
                    for key, value in mmap_entry_counts(item['counters']).items():
                        row['mmap_' + key] = value
            # Different useful-work units, such as bytes and node visits, stay separate.
            for metric in ('file_read_bytes', 'memory_node_visits'):
                av = a['result']['metrics'].get('progress', {}).get(metric)
                bv = b['result']['metrics'].get('progress', {}).get(metric)
                if av and bv:
                    ar = av / (a['result']['wall_ns'] / 1e9)
                    br = bv / (b['result']['wall_ns'] / 1e9)
                    row[metric + '_baseline_rate'] = ar
                    row[metric + '_probe_rate'] = br
                    row[metric + '_throughput_loss_percent'] = 100 * (1 - br / ar)
        pairs.append(row)
    numeric = [
        key
        for key, value in pairs[0].items()
        if key != 'repeat'
        and isinstance(value, (int, float))
        and all(isinstance(row.get(key), (int, float)) for row in pairs)
    ]
    summary = dict(
        schema_version=1,
        workload=rows[0]['workload'],
        cpu_scope=rows[0]['cpu_scope'],
        observer_scope='host',
        observers=observers or {},
        pairs=len(pairs),
        observed=all('probe' in arms for arms in groups.values()),
        statistics={key: describe([row[key] for row in pairs]) for key in numeric},
        paired_rounds=pairs,
        notes=[
            'Statistics are computed per pair before taking medians.',
            'Observer event counts describe the whole host, not only the workload.',
            'Negative increments and losses do not prove that observation is free.',
        ],
    )
    if write:
        (folder / 'summary.json').write_text(
            json.dumps(summary, ensure_ascii=False, indent=2) + '\n', encoding='utf-8'
        )
        with (folder / 'rounds.csv').open('w', newline='', encoding='utf-8') as stream:
            writer = csv.DictWriter(stream, fieldnames=list(pairs[0]))
            writer.writeheader()
            writer.writerows(pairs)
    return summary
