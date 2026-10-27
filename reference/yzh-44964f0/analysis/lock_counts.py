"""Mmap entry counters shared by offline comparisons and experiment summaries."""


def count_value(value):
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def mmap_entry_counts(counters):
    result = {}
    for direction in ('read', 'write'):
        total = count_value(counters.get('total_' + direction + '_start'))
        matched = count_value(counters.get('match_' + direction + '_start'))
        result['total_' + direction + '_start'] = total
        result['match_' + direction + '_start'] = matched
        result[direction + '_hit_percent'] = (
            100 * matched / total if total is not None and total > 0 and matched is not None else None
        )
    return result


def count_text(value):
    if value is None:
        return '未记录'
    if isinstance(value, int):
        return f'{value:,}'
    return f'{value:,.1f}'.removesuffix('.0')


def rate_text(rate, total, matched):
    if total is None or matched is None:
        return '未记录'
    return f'{rate:.2f}%' if rate is not None else '—'
