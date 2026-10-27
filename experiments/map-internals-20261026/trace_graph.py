"""Private function-graph instance; never configure the main tracing instance."""
from pathlib import Path
import errno
import json
import os
import uuid


FUNCTIONS = ('htab_map_update_elem', 'htab_map_update_elem_in_place', 'alloc_htab_elem',
             '___pcpu_freelist_pop', '__pcpu_freelist_pop',
             'native_queued_spin_lock_slowpath', '__cna_queued_spin_lock_slowpath',
             'queued_spin_lock_slowpath', '__queued_spin_lock_slowpath',
             '__pv_queued_spin_lock_slowpath')


class GraphUnavailable(RuntimeError):
    pass


class MapGraph:
    def __init__(self, directory, tids):
        self.directory = Path(directory)
        self.root = next((p for p in (Path('/sys/kernel/tracing'), Path('/sys/kernel/debug/tracing'))
                          if (p / 'available_filter_functions').is_file()), Path('/sys/kernel/tracing'))
        if not (self.root / 'available_filter_functions').is_file():
            raise GraphUnavailable('Mounted tracefs with function tracing is unavailable')
        self.original_tracer = (self.root / 'current_tracer').read_text()
        self.original_options = (self.root / 'trace_options').read_text()
        names = {line.split()[0] for line in
                 (self.root / 'available_filter_functions').read_text().splitlines()}
        self.functions = [name for name in FUNCTIONS if name in names]
        if not {'htab_map_update_elem', 'alloc_htab_elem'} <= set(self.functions):
            raise GraphUnavailable('Hash update/allocation are not traceable on this kernel')
        self.path = self.root / 'instances' / ('map-internals-' + str(os.getpid()) + '-' + uuid.uuid4().hex[:8])
        self.path.mkdir()
        capability = dict(root=str(self.root), main_tracer=self.original_tracer.strip(),
                          selected_functions=self.functions, instance=str(self.path))
        try:
            self.write('tracing_on', '0')
            capability['instance_available_tracers'] = (self.path / 'available_tracers').read_text().split()
            if 'function_graph' not in capability['instance_available_tracers']:
                raise GraphUnavailable('This kernel does not offer function_graph in a private instance; global tracer was not changed')
            self.write('buffer_size_kb', '2048')
            try:
                self.write('current_tracer', 'function_graph')
            except OSError as exc:
                if exc.errno in (errno.EINVAL, errno.ENODEV, errno.ENOSYS, errno.EOPNOTSUPP):
                    raise GraphUnavailable('Private-instance function_graph rejected: ' + str(exc)) from exc
                raise
            self.write('set_ftrace_filter', '\n'.join(self.functions))
            self.write('set_ftrace_pid', '\n'.join(map(str, tids)))
            for name, value in (('funcgraph-proc', '1'), ('funcgraph-irqs', '0'),
                                ('funcgraph-abstime', '1'), ('funcgraph-duration', '1')):
                if (self.path / 'options' / name).exists():
                    self.write('options/' + name, value)
            self.write('trace', '')
            capability['supported'] = True
        except BaseException as exc:
            capability.update(supported=False, error=repr(exc))
            self.close()
            capability['main_configuration_unchanged'] = True
            (self.directory / 'graph-capability.json').write_text(json.dumps(capability, indent=2))
            raise
        (self.directory / 'graph-capability.json').write_text(json.dumps(capability, indent=2))

    def write(self, name, value):
        (self.path / name).write_text(value)

    def start(self):
        self.write('tracing_on', '1')

    def stop(self):
        self.write('tracing_on', '0')
        trace = (self.path / 'trace').read_text()
        stats = {p.parent.name: p.read_text() for p in
                 (self.path / 'per_cpu').glob('cpu*/stats')}
        (self.directory / 'map-function-graph.txt').write_text(trace)
        return dict(functions=self.functions, instance=str(self.path), per_cpu_stats=stats)

    def close(self):
        if self.path.exists():
            self.write('tracing_on', '0')
            self.write('current_tracer', 'nop')
            self.path.rmdir()
        if ((self.root / 'current_tracer').read_text() != self.original_tracer or
                (self.root / 'trace_options').read_text() != self.original_options):
            raise RuntimeError('The main tracing configuration changed')
