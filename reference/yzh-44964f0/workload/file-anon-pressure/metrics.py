"""Read the ARM64 little-endian, aligned per-worker counters (no BPF required)."""

import struct

MAGIC = 0x56414E4F56455231


def decode(data):
    if len(data) < 128:
        raise ValueError('Progress header missing')
    magic, collecting, ready, workers, start_ns, stop_ns = struct.unpack_from('<6Q', data)
    if magic != MAGIC or len(data) != (workers + 1) * 128:
        raise ValueError('Progress layout mismatch')
    result = {
        'workers': workers,
        'ready': ready,
        'collecting': collecting,
        'start_ns': start_ns,
        'stop_ns': stop_ns,
        'file_workers': 0,
        'memory_workers': 0,
        'file_words': 0,
        'memory_node_visits': 0,
        'allocated_nodes': 0,
        'file_iterations': 0,
        'memory_iterations': 0,
        'prepared_file_bytes': 0,
        'initial_memory_nodes': 0,
    }
    for i in range(workers):
        visits, allocated, iterations, is_ready, kind, file_bytes, nodes = struct.unpack_from(
            '<7Q', data, 128 * (i + 1)
        )
        if is_ready != 1 or kind not in (1, 2):
            raise ValueError(f'Worker {i} not ready')
        if kind == 1:
            result['file_workers'] += 1
            result['file_words'] += visits
            result['file_iterations'] += iterations
            result['prepared_file_bytes'] += file_bytes
        else:
            result['memory_workers'] += 1
            result['memory_node_visits'] += visits
            result['memory_iterations'] += iterations
            result['initial_memory_nodes'] += nodes
        result['allocated_nodes'] += allocated
    result['file_read_bytes'] = result['file_words'] * 8
    return result


def rates(progress):
    elapsed = (progress['stop_ns'] - progress['start_ns']) / 1e9
    if elapsed <= 0:
        raise ValueError('Invalid active window')
    return {
        'active_wall_s': elapsed,
        'file_read_gib_s': progress['file_read_bytes'] / 1024**3 / elapsed,
        'memory_million_nodes_s': progress['memory_node_visits'] / 1e6 / elapsed,
        'new_nodes_per_s': progress['allocated_nodes'] / elapsed,
    }
