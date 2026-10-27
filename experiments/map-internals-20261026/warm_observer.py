"""Keep pairing/counter validation while exporting the added warming work."""
import ctypes
from dataclasses import replace
import json
import os
from pathlib import Path
import struct
import subprocess
import sys

HERE = Path(__file__).resolve().parent
BASE = HERE.parent / 'mmap-cause-20261026'
sys.path.insert(0, str(BASE))
import diagnostic_observer as original
from program_stats import read_fd

MODE = 'none'


class WarmObserver(original.DiagnosticObserver):
    def __init__(self, selection, directory, live=False):
        super().__init__(selection, directory, live)
        self.selection = replace(self.selection, object=HERE / (MODE + '.bpf.o'))
        self.warm_fd = -1

    def prepare(self):
        super().prepare()
        for path in Path(f'/proc/{self.process.pid}/fdinfo').iterdir():
            values = read_fd(path)
            if values.get('value_size') != '48' or values.get('max_entries') != '2' or 'map_id' not in values:
                continue
            info = json.loads(subprocess.check_output(['bpftool', '-j', 'map', 'show', 'id', values['map_id']], text=True))
            if isinstance(info, list):
                info = info[0]
            if info['name'] == 'diag_warm':
                self.warm_fd = self.lib.bpf_map_get_fd_by_id(int(values['map_id']))
                break
        if self.warm_fd < 0:
            raise RuntimeError('Warming statistics map not found')

    def stop(self):
        super().stop()
        slots = []
        identities = []
        for slot in range(2):
            key = ctypes.c_uint32(slot)
            value = ctypes.create_string_buffer(48 * self.cpus)
            if self.lib.bpf_map_lookup_elem(self.warm_fd, ctypes.byref(key), value):
                raise OSError(ctypes.get_errno(), 'Cannot read warming counters')
            entries = list(struct.iter_unpack('=QQQQQQ', value.raw))
            identities.extend(dict(slot=slot, cpu=cpu, raw_tgid=x[4], raw_tid=x[5])
                              for cpu, x in enumerate(entries) if x[0])
            slots.append(dict(zip(('calls', 'ns', 'errors', 'hits'),
                                  (sum(x[i] for x in entries) for i in range(4)))))
        d = self.value['diagnostic']
        assert sum(s['calls'] for s in slots) == d['calls']
        assert not any(s['errors'] or s['hits'] for s in slots), slots
        result = dict(mode=MODE, slots=slots, last_raw_identity_by_cpu=identities,
                      interpretation='Warming is additional work before the timed insertion, not a production optimization; its CPU time is retained separately.')
        self.value['warming'] = result
        (self.directory / 'warming.json').write_text(json.dumps(result, indent=2))

    def close(self):
        try:
            super().close()
        finally:
            if self.warm_fd >= 0:
                os.close(self.warm_fd)
                self.warm_fd = -1
