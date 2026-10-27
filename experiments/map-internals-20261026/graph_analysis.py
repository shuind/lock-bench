"""Decode selected function-graph records; durations retain tracing overhead."""
import re

ROOTS = {'htab_map_update_elem', 'htab_map_update_elem_in_place'}
LINE = re.compile(r'^\s*[\d.]+\s+\|\s*(\d+)\)\s+(.+?)-(\d+)\s+\|\s*(.*?)\|\s*(.*)$')
FUNCTION = re.compile(r'([\w.]+)\(\)\s*([;{])')
DURATION = re.compile(r'([\d.]+)\s+us')


def decode(text, tids):
    stacks, roots, unparsed = {}, [], []
    for line in text.splitlines():
        match = LINE.match(line)
        if not match:
            continue
        cpu, comm, tid, duration, body = match.groups()
        tid = int(tid)
        if tid not in tids:
            continue
        stack = stacks.setdefault(tid, [])
        dt = DURATION.search(duration)
        ns = int(round(float(dt.group(1)) * 1000)) if dt else None
        fn = FUNCTION.search(body)
        if fn:
            name, kind = fn.groups()
            entry = dict(function=name, tid=tid, cpu=int(cpu), children=[], ns=ns)
            if kind == '{':
                stack.append(entry)
                continue
        elif body.startswith('}'):
            if not stack:
                unparsed.append(line)
                continue
            entry = stack.pop()
            entry['ns'] = ns
        else:
            continue
        if entry['ns'] is None:
            unparsed.append(line)
        if stack:
            stack[-1]['children'].append(entry)
        elif entry['function'] in ROOTS:
            roots.append(entry)
    incomplete = {str(tid): entries for tid, entries in stacks.items() if entries}
    functions = {}

    def add(entry):
        row = functions.setdefault(entry['function'], dict(calls=0, total_ns=0))
        row['calls'] += 1
        row['total_ns'] += entry['ns'] or 0
        for child in entry['children']:
            add(child)
    for root in roots:
        add(root)
    for row in functions.values():
        row['mean_ns'] = row['total_ns'] / row['calls']
    return dict(roots=len(roots), functions=functions, incomplete=incomplete,
                unparsed=unparsed, records=roots,
                interpretation='Inclusive function-graph times, with tracing overhead; nested function times must not be added together.')
