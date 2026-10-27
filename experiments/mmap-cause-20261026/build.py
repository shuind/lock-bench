"""Build segmented and total-only controls; reuse the current native collector."""
from pathlib import Path
import platform
import shutil
import subprocess

HERE=Path(__file__).resolve().parent
BASE=HERE.parent/'bpf-callbacks-20261026'
for name in ('source','fixtures','kernel','tools'):
    target=BASE/name;dest=HERE/name
    if not target.exists():
        if name=='tools':continue
        raise SystemExit('Missing prepared input: '+str(target))
    if not dest.exists():dest.symlink_to(target,target_is_directory=True)
    if dest.resolve()!=target.resolve():raise SystemExit('Unexpected input: '+str(dest))
for name in ('http_measure.py','kbuild_measure.py','program_stats.py','http/controller.py','http/server.py'):
    dest=HERE/name;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(BASE/name,dest)
SOURCE=HERE/'source';COPY=HERE/'instrumented'
for path in (SOURCE/'observer').rglob('*'):
    if path.is_file()and path.suffix in ('.c','.h')and not any(x in path.parts for x in ('dist','.build')):
        dest=COPY/path.relative_to(SOURCE);dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(path,dest)


def once(s,old,new):
    if s.count(old)!=1:raise ValueError('Expected one fragment: '+old)
    return s.replace(old,new,1)


# The service and its 32 workers inherit a requested test affinity, while the
# controller/clients retain their normal placement. Preserve the request path.
server=HERE/'http/server.py';s=server.read_text()
s=once(s,'STOP=False','STOP=False\nif os.environ.get("DIAGNOSTIC_SERVICE_CPUS"):\n    os.sched_setaffinity(0,{int(x) for x in os.environ["DIAGNOSTIC_SERVICE_CPUS"].split(",")})')
server.write_text(s)

# Start make behind a tiny native gate: retain a known root PID before exec and
# descendants, then let it run only after configuring the diagnostic filter.
kb=HERE/'kbuild_measure.py';s=kb.read_text()
s=once(s,'import signal','import signal\nimport socket')
old='            process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT, env=env, preexec_fn=ordinary_account)'
new='''            parent_gate,child_gate=socket.socketpair()
            process = subprocess.Popen([str(HERE/'gate-exec'),*command], stdout=log, stderr=subprocess.STDOUT,
                    env=dict(env,DIAGNOSTIC_GATE_FD=str(child_gate.fileno())),pass_fds=(child_gate.fileno(),),preexec_fn=ordinary_account)
            child_gate.close();parent_gate.settimeout(15)
            if parent_gate.recv(1)!=b'R':raise RuntimeError('Kbuild gate not ready')
            observer.set_profile_root(process.pid,True)
            if os.environ.get('DIAGNOSTIC_WORKLOAD_CPUS'):
                os.sched_setaffinity(process.pid,{int(x)for x in os.environ['DIAGNOSTIC_WORKLOAD_CPUS'].split(',')})
            parent_gate.sendall(b'G');parent_gate.close()'''
s=once(s,old,new)
s=once(s,'                   combined_cpu_s=cpu + observer_cpu + controller_cpu, headers=len(headers),',
       '                   combined_cpu_s=cpu + observer_cpu + controller_cpu, headers=len(headers),\n                   voluntary_switches=usage.ru_nvcsw,involuntary_switches=usage.ru_nivcsw,')
kb.write_text(s)

header=(HERE/'diagnostic.h').read_text();arch={'x86_64':'x86','aarch64':'arm64'}[platform.machine()]
for method in ('fentry','tracepoint'):
    path=COPY/f'observer/mmap/{method}/probe.bpf.c';s=path.read_text()
    s=once(s,'#include "../state.bpf.h"','#include "../state.bpf.h"\n'+header)
    if method=='fentry':
        old='{struct counter_values *c=counts_get();on_start(c,ctx,(__u64)sem,write);return 0;}'
        new='''{if(id!=4) {struct counter_values *c=counts_get();on_start(c,ctx,(__u64)sem,write);return 0;}
    struct diagnostic_marks mark={0};mark.time[0]=bpf_ktime_get_ns();struct counter_values *c=counts_get();
    bool accepted=diagnostic_start(c,ctx,(__u64)sem,false,&mark);if(accepted)diagnostic_finish(&mark);return 0;}'''.replace('\n',' ')
        s=once(s,old,new)
    else:
        at=s.index('int mt_start(');start=s.index('{',at);end=s.index('}',start)+1
        s=s[:start]+'''{if(!ctx->write) {struct counter_values *c=counts_get();mm_start(c,ctx,(__u64)ctx->mm+bpf_core_field_offset(struct mm_struct,mmap_lock),false,true);return 0;}
    struct diagnostic_marks mark={0};mark.time[0]=bpf_ktime_get_ns();struct counter_values *c=counts_get();
    bool accepted=diagnostic_start(c,ctx,(__u64)ctx->mm+bpf_core_field_offset(struct mm_struct,mmap_lock),true,&mark);
    if(accepted)diagnostic_finish(&mark);return 0;}'''+s[end:]
    path.write_text(s)
    for total in (False,True):
        label='total'if total else'segments'
        subprocess.run(['clang','-O2','-g','-target','bpf','-D__TARGET_ARCH_'+arch,'-DDIAG_TOTAL_ONLY='+str(int(total)),
                        '-I'+str(SOURCE/'observer/.build'),'-I'+str(SOURCE/'observer/common'),'-c',str(path),
                        '-o',str(HERE/(method+'-'+label+'.bpf.o'))],check=True)
        print('DIAGNOSTIC_OBJECT_BUILT',method,label,flush=True)
subprocess.run(['gcc','-O2','-g','-Wall','-Wextra','-Werror','-Wno-deprecated-declarations','-pthread',str(HERE/'controlled.c'),'-o',str(HERE/'controlled'),'-lcrypto'],check=True)
subprocess.run(['gcc','-O2','-Wall','-Wextra','-Werror',str(HERE/'gate_exec.c'),'-o',str(HERE/'gate-exec')],check=True)
print('DIAGNOSTIC_BUILD_PASS',flush=True)
