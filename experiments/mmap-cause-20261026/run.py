"""Find the component and execution conditions behind workload-dependent cost."""
import argparse
import ctypes
import json
import os
from pathlib import Path
import pwd
import random
import select
import shutil
import statistics
import subprocess
import sys
import tempfile
import time

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE/'source'))
from observer.catalog import backends,Selection
import diagnostic_observer as diagnostic
import http_measure
import kbuild_measure

http_measure.NativeObserver=kbuild_measure.NativeObserver=diagnostic.DiagnosticObserver
COMPONENTS=('front','identity_and_record','map_insert','finish')


def dump(path,value):path.write_text(json.dumps(value,indent=2,ensure_ascii=False)+'\n')
def flag():return Path('/proc/sys/kernel/bpf_stats_enabled').read_text().strip()


def system_snapshot():
    cpu={};other={}
    for line in Path('/proc/stat').read_text().splitlines():
        fields=line.split()
        if fields[0].startswith('cpu'):cpu[fields[0]]=list(map(int,fields[1:9]))
        elif fields[0]in('ctxt','processes','procs_running','procs_blocked'):other[fields[0]]=int(fields[1])
    soft={line.split(':')[0].strip():list(map(int,line.split(':')[1].split()))for line in Path('/proc/softirqs').read_text().splitlines()[1:]}
    return dict(monotonic_ns=time.monotonic_ns(),cpu=cpu,other=other,softirq=soft)


def system_delta(a,b):
    cpu={}
    for name,values in a['cpu'].items():
        delta=[y-x for x,y in zip(values,b['cpu'][name])];total=sum(delta)
        cpu[name]=dict(ticks=delta,total_ticks=total,steal_pct=delta[7]/total*100 if total else None,
             busy_pct=(total-delta[3]-delta[4]-delta[7])/total*100 if total else None)
    return dict(cpu=cpu,context_switches=b['other']['ctxt']-a['other']['ctxt'],
                softirq={name:[y-x for x,y in zip(a['softirq'][name],v)]for name,v in b['softirq'].items()})


def receive(p):
    if not select.select([p.stdout],[],[],30)[0]:raise TimeoutError('Controlled workload handshake')
    line=p.stdout.readline()
    if not line:raise RuntimeError('Controlled workload exited: '+p.stderr.read()[-2000:])
    return json.loads(line)


def native_measure(out,case,repeat,cpus):
    directory=out/f'r{repeat+1}-{case["name"]}';directory.mkdir()
    uid=int(os.environ.get('SUDO_UID',os.getuid()));gid=pwd.getpwuid(uid).pw_gid
    def setup():
        os.setsid();os.sched_setaffinity(0,cpus)
        if os.geteuid()==0:os.setgroups([]);os.setgid(gid);os.setuid(uid)
    process=subprocess.Popen([str(HERE/'controlled'),str(case['threads']),str(case['operations']),case['work']],
         stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,preexec_fn=setup)
    observer=None
    try:
        assert receive(process)['phase']=='ready'
        product=backends()['mmap/fentry']
        selected=Selection(product,True,'count','none',100000000,100,'both',None,product.object,event_counts=True)
        observer=diagnostic.DiagnosticObserver(selected,directory/'collector');observer.prepare()
        observer.set_profile_root(process.pid,False);observer.start()
        start=time.monotonic_ns();process.stdin.write('G');process.stdin.flush();work=receive(process)
        wall=time.monotonic_ns()-start
        observer.stop();observed=observer.result()
        assert not work['error']and work['operations']==case['operations']
        measured=observed['diagnostic']['calls']
        assert case['operations']<=measured<=case['operations']+case['threads']*4+16,(case,work,measured)
        if case.get('paired'):assert measured==case['operations']
        process.stdin.write('F');process.stdin.flush();assert process.wait(timeout=15)==0
        errors={k:v for k,v in observed['counters'].items()if v and(k.endswith('errors')or k in('ring_dropped','mm_duplicate','mm_aborted'))}
        if observed.get('retprobe_misses'):errors['retprobe_misses']=observed['retprobe_misses']
        if observed.get('mmap_cleanup_errors'):errors['mmap_cleanup_errors']=observed['mmap_cleanup_errors']
        assert not errors,errors
        value=dict(wall_ns=wall,workload=work,observation=observed,errors=errors,affinity=cpus)
        dump(directory/'measurement.json',value);return value
    finally:
        if observer:observer.close()
        if process.poll()is None:
            try:process.stdin.write('F');process.stdin.flush();process.wait(timeout=5)
            except Exception:process.kill();process.wait()


def describe(v):
    if not v:return dict(median=None,madn=None,min=None,max=None,rounds=[])
    mid=statistics.median(v)
    return dict(median=mid,madn=statistics.median(abs(x-mid)for x in v)/0.6744897501960817,min=min(v),max=max(v),rounds=v)


def summarize(out,rows):
    summaries=[]
    for name in sorted({r['case']['name']for r in rows}):
        group=sorted((r for r in rows if r['case']['name']==name),key=lambda r:r['repeat'])
        result=dict(case=group[0]['case'],rounds=len(group),calls=describe([r['diagnostic']['calls']for r in group]),
            total_ns=describe([r['diagnostic']['mean_ns']for r in group]),
            empty_ns=describe([r['diagnostic']['empty_reference_ns']for r in group]),components={})
        for part in COMPONENTS:
            result['components'][part]=describe([next(p['mean_ns']for p in r['diagnostic']['components']if p['name']==part)for r in group])
        summaries.append(result)
    dump(out/'summary.json',summaries)
    lines=['Scoped write START component timings, ns. Means per run, then median across runs.',
           'case | mode | calls | front | identity/record | insert | finish | total | clock reference | total MADN']
    for row in summaries:
        c=row['components'];lines.append(row['case']['name']+' | '+row['case']['mode']+' | '+str(row['calls']['median'])+' | '+
             ' | '.join(f"{c[n]['median']:.2f}"for n in COMPONENTS)+f" | {row['total_ns']['median']:.2f} | {row['empty_ns']['median']:.2f} | {row['total_ns']['madn']:.2f}")
    (out/'SUMMARY.txt').write_text('\n'.join(lines)+'\n')


def cases():
    result=[]
    for method in('fentry','tracepoint'):
        for workload in('kbuild','http-32'):
            result.append(dict(name=method+'-'+workload,method=method,workload=workload,policy='default',mode='segments'))
            if method=='fentry':
                result.append(dict(name=method+'-'+workload+'-pinned',method=method,workload=workload,policy='single',mode='segments'))
                result.append(dict(name=method+'-'+workload+'-total',method=method,workload=workload,policy='default',mode='total'))
    for work,threads,policy,n in(('hot',1,'single',65536),('hot',32,'all',65536),('hot',32,'single',65536),
                                 ('sleep',1,'single',1024),('busy',1,'single',1024),('hash',1,'single',1024),
                                 ('hash-small',1,'single',1024),('pair-hot',1,'single',65536),('pair-hash',1,'single',2048)):
        result.append(dict(name=f'native-{work}-{threads}-{policy}',method='fentry',workload='native',policy=policy,
                           mode='segments',work=work,threads=threads,operations=n,paired=work.startswith('pair-')))
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rounds',type=int,default=3);parser.add_argument('--local-smoke',action='store_true')
    parser.add_argument('--only',nargs='+')
    args=parser.parse_args()
    if os.geteuid():parser.error('Root is required to load profiling objects')
    if args.rounds<1:parser.error('Invalid rounds')
    http_measure.guard_active_experiments()
    allowed=sorted(os.sched_getaffinity(0));single=allowed[:1]
    if not allowed:parser.error('No allowed CPU')
    os.environ['PATH']=str(HERE/'tools/usr/bin')+os.pathsep+os.environ['PATH']
    original=flag();stats_fd=-1
    if original!='1':
        if not args.local_smoke or os.uname().machine=='aarch64':parser.error('Existing bpf_stats_enabled must be 1; no setting changed')
        lib=ctypes.CDLL('libbpf.so.1',use_errno=True);stats_fd=lib.bpf_enable_stats(0)
        if stats_fd<0:raise OSError(ctypes.get_errno(),'Cannot temporarily enable local statistics')
    out=Path(tempfile.mkdtemp(prefix=time.strftime('results-%Y%m%d-%H%M%S-'),dir=HERE))
    uid=int(os.environ.get('SUDO_UID',os.getuid()));os.chown(out,uid,pwd.getpwuid(uid).pw_gid);out.chmod(0o755)
    plan=cases()
    if args.only:
        if not set(args.only)<={c['name']for c in plan}:parser.error('Unknown case')
        plan=[c for c in plan if c['name']in args.only]
    rounds=1 if args.local_smoke else args.rounds
    metadata=dict(kernel=os.uname().release,machine=os.uname().machine,observer_commit='57326bc',cases=plan,
        rounds=rounds,local_functional_smoke=args.local_smoke,bpf_stats_enabled=original,temporary_local_stats_fd=stats_fd>=0,
        allowed_cpus=allowed,pinned_cpu=single,collect='count',timeout='none',event_counts='on',
        scope='Diagnostic timings limited to HTTP service TGID or make descendants/native TGID; collector itself remains host-wide',
        components=list(COMPONENTS),http_requests=128 if args.local_smoke else 2048,
        interpretation='Private component instrumentation plus total-only control, fixed CPU comparisons and controlled syscall spacing; checkpoint overhead retained')
    if shutil.which('perf'):
        probe=subprocess.run(['perf','stat','-x,','-e','cycles:u,instructions:u','--','true'],capture_output=True,text=True)
        metadata['perf_hardware_probe']=dict(returncode=probe.returncode,text=probe.stderr)
    else:metadata['perf_hardware_probe']=dict(returncode=None,text='perf unavailable')
    metadata['cpufreq']={str(p):p.read_text().strip()for p in Path('/sys/devices/system/cpu').glob('cpu[0-9]*/cpufreq/scaling_cur_freq')}
    dump(out/'metadata.json',metadata);print('RESULTS:',out,flush=True);rows=[]
    try:
        schedule=[];rng=random.Random(2026102607)
        for repeat in range(rounds):
            block=list(plan);rng.shuffle(block);schedule.extend((repeat,c)for c in block)
        dump(out/'schedule.json',[dict(repeat=n,case=c)for n,c in schedule])
        for repeat,case in schedule:
            if flag()!=original:raise RuntimeError('Runtime statistics setting changed externally')
            diagnostic.MODE=case['mode']
            diagnostic.PAIRED=case.get('paired',False)
            for key in('DIAGNOSTIC_SERVICE_CPUS','DIAGNOSTIC_WORKLOAD_CPUS'):os.environ.pop(key,None)
            if case['policy']=='single':
                os.environ['DIAGNOSTIC_SERVICE_CPUS']=','.join(map(str,single));os.environ['DIAGNOSTIC_WORKLOAD_CPUS']=','.join(map(str,single))
            before=system_snapshot()
            if case['workload']=='native':measurement=native_measure(out,case,repeat,single if case['policy']=='single'else allowed)
            elif case['workload']=='http-32':
                http_measure.CLIENTS=32;os.environ['HTTP_WORKERS']='32'
                measurement=http_measure.measure(out,case['method'],True,repeat,metadata['http_requests'],case['name'],original)
            else:
                measurement=kbuild_measure.measure(out,argparse.Namespace(jobs=1,collect='count',timeout='none'),
                            case['method'],'C',repeat,case['name'])
            after=system_snapshot()
            if flag()!=original:raise RuntimeError('Runtime statistics setting changed externally')
            observed=measurement.get('observation',measurement.get('observer'))
            record=dict(case=case,repeat=repeat,diagnostic=observed['diagnostic'],measurement=measurement,
                        system_before=before,system_after=after,system_delta=system_delta(before,after))
            rows.append(record);dump(out/'rows.json',rows);summarize(out,rows)
            print(f"[{len(rows)}/{len(schedule)}] {case['name']}: scoped={record['diagnostic']['calls']}; total={record['diagnostic']['mean_ns']:.2f}ns",flush=True)
        dump(out/'completed.json',dict(checks='PASS',runs=len(rows),expected_runs=len(schedule),original_sysctl=original,final_sysctl=flag(),local_functional_smoke=args.local_smoke))
        print('MMAP_CAUSE_DIAGNOSIS_COMPLETE',flush=True)
    except BaseException as exc:
        dump(out/'failure.json',dict(error=repr(exc),completed_runs=len(rows)));raise
    finally:
        if stats_fd>=0:os.close(stats_fd)


if __name__=='__main__':main()
