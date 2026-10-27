"""Build private map-warming controls from the already measured collector."""
from pathlib import Path
import platform
import shutil
import subprocess

HERE = Path(__file__).resolve().parent
BASE = HERE.parent / 'mmap-cause-20261026'
old = (BASE / 'diagnostic.h').read_text()
header = old.replace(
    'struct diagnostic_marks { __u64 time[5]; };',
    '''struct diagnostic_marks { __u64 time[5]; __u64 warm_ns; __u32 warm_errors, warm_hits; };
struct warm_sample { __u64 calls, ns, errors, hits, raw_tgid, raw_tid; };
struct { __uint(type,BPF_MAP_TYPE_PERCPU_ARRAY); __uint(max_entries,2);
    __type(key,__u32); __type(value,struct warm_sample); } diag_warm SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_HASH); __uint(max_entries,8192);
    __type(key,struct mmap_key); __type(value,struct record); } warm_twin SEC(".maps");

static __always_inline void warm_before_insert(const struct mmap_key *key,struct diagnostic_marks *m) {
#if WARM_MODE
    __u64 start=bpf_ktime_get_ns();
#if WARM_MODE==1
    m->warm_hits=bpf_map_lookup_elem(&mm_records,key)!=0;
#elif WARM_MODE==2
    m->warm_hits=bpf_map_lookup_elem(&warm_twin,key)!=0;
#elif WARM_MODE>=3
    // This key cannot be produced by a real mmap event (sem/task are nonzero).
    struct mmap_key scratch=mmap_key_make(0x1000 + bpf_get_smp_processor_id()*8,0,0,0);
    struct record value={.stack_id=-1,.stage=1};
#if WARM_MODE==3
    m->warm_errors=bpf_map_update_elem(&mm_records,&scratch,&value,BPF_NOEXIST)!=0;
    m->warm_errors+=bpf_map_delete_elem(&mm_records,&scratch)!=0;
#else
    m->warm_errors=bpf_map_update_elem(&warm_twin,&scratch,&value,BPF_NOEXIST)!=0;
    m->warm_errors+=bpf_map_delete_elem(&warm_twin,&scratch)!=0;
#endif
#endif
    m->warm_ns=bpf_ktime_get_ns()-start;
#endif
}''')
assert header != old
needle = 'struct diagnostic_sample *sample=bpf_map_lookup_elem(&diag_samples,&slot);'
assert header.count(needle) == 1
header = header.replace(needle, '''struct warm_sample *w=bpf_map_lookup_elem(&diag_warm,&slot);
    if(w) {w->calls++;w->ns+=m->warm_ns;w->errors+=m->warm_errors;w->hits+=m->warm_hits;
        struct task_struct *task=mm_task();w->raw_tgid=BPF_CORE_READ(task,tgid);w->raw_tid=BPF_CORE_READ(task,pid);}
    ''' + needle)
needle = 'm->time[2]=bpf_ktime_get_ns();'
assert header.count(needle) == 1
header = header.replace(needle, 'warm_before_insert(&key,m);' + needle)
source = (BASE / 'instrumented/observer/mmap/fentry/probe.bpf.c').read_text()
assert source.count(old) == 1
source = source.replace(old, header)
copy = HERE / 'instrumented'
for path in (BASE / 'instrumented/observer').rglob('*'):
    if path.is_file() and path.suffix in ('.c', '.h'):
        dest = copy / path.relative_to(BASE / 'instrumented')
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, dest)
probe = copy / 'observer/mmap/fentry/probe.bpf.c'
probe.write_text(source)
arch = {'aarch64': 'arm64', 'x86_64': 'x86'}[platform.machine()]
for mode, name in enumerate(('none', 'lookup-target', 'lookup-other', 'recycle-node', 'recycle-other')):
    subprocess.run(['clang', '-O2', '-g', '-target', 'bpf', '-D__TARGET_ARCH_' + arch,
                    '-DDIAG_TOTAL_ONLY=0', '-DWARM_MODE=' + str(mode),
                    '-I' + str(BASE / 'source/observer/.build'),
                    '-I' + str(BASE / 'source/observer/common'), '-c', str(probe),
                    '-o', str(HERE / (name + '.bpf.o'))], check=True)
    print('BUILT', name, flush=True)
