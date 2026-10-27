"""Measure current unmodified observer on the unchanged HTTP checksum workload."""
import argparse
import csv
import ctypes
import json
import os
from pathlib import Path
import pwd
import random
import select
import shutil
import signal
import socket
import statistics
import struct
import subprocess
import sys
import tempfile
import time

HERE=Path(__file__).resolve().parent
SOURCE=HERE/'source'
sys.path.insert(0,str(SOURCE))
from observer.catalog import backends,Selection
from observer.native import NativeObserver

METHODS=('tracepoint',)
CLIENTS=32
KEYS=('total_read_start','total_write_start','total_read_return','total_write_return',
      'total_read_release','total_write_release','total_downgrade')
ERRORS=('state_errors','stack_errors','pair_errors','timer_errors','ring_dropped','mm_duplicate','mm_aborted')
LIBC=ctypes.CDLL(None)

def dump(path,value):
    path.write_text(json.dumps(value,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')

def status(message):
    print(time.strftime('%H:%M:%S'),message,flush=True)

def flag():
    return Path('/proc/sys/kernel/bpf_stats_enabled').read_text().strip()

def clock(pid):
    value=ctypes.c_int()
    error=LIBC.clock_getcpuclockid(pid,ctypes.byref(value))
    if error:raise OSError(error,os.strerror(error))
    return value.value

def read_exact(channel,size,seconds):
    result=b'';deadline=time.monotonic()+seconds
    while len(result)<size:
        wait=deadline-time.monotonic()
        if wait<=0 or not select.select([channel],[],[],max(0,wait))[0]:
            raise TimeoutError('HTTP workload phase timed out')
        piece=channel.recv(size-len(result))
        if not piece:raise RuntimeError('HTTP controller exited before completing its protocol')
        result+=piece
    return result

def stop(process):
    if process and process.poll() is None:
        try:os.killpg(process.pid,signal.SIGTERM)
        except ProcessLookupError:return
        try:process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid,signal.SIGKILL);process.wait(timeout=5)

def med(values):
    middle=statistics.median(values)
    return dict(median=middle,madn=statistics.median(abs(v-middle) for v in values)/0.6744897501960817,
                min=min(values),max=max(values),rounds=values)

def summarize(out,rows):
    summaries=[]
    for method in METHODS:
        indexes=sorted({r['repeat'] for r in rows if r['method']==method})
        pairs=[]
        for n in indexes:
            group={r['observe']:r for r in rows if r['method']==method and r['repeat']==n}
            if set(group)=={False,True}:pairs.append(group)
        if not pairs:continue
        item=dict(method=method,complete_pairs=len(pairs),metrics={})
        for metric in ('test_cpu_ns','service_cpu_ns','client_cpu_ns','controller_cpu_ns',
                       'observer_cpu_ns','combined_cpu_ns','wall_ns'):
            b=[p[False][metric]/1e6 for p in pairs];c=[p[True][metric]/1e6 for p in pairs]
            delta=[y-x for x,y in zip(b,c)]
            item['metrics'][metric]=dict(baseline_ms=med(b),probe_ms=med(c),delta_ms=med(delta),
                                         overhead_pct=med([(y-x)/x*100 for x,y in zip(b,c) if x>0]))
        on=[p[True] for p in pairs]
        item['counts']={k:med([r['counters'][k] for r in on]) for k in
                        (*KEYS,'match_read_start','match_write_start','match_read_acquire','match_write_acquire','match_downgrade')}
        item['callbacks']=med([r['main_callbacks'] for r in on])
        summaries.append(item)
    dump(out/'summary.json',summaries)
    keys=['label','method','repeat','observe','requests','wall_ns','test_cpu_ns','service_cpu_ns',
          'client_cpu_ns','controller_cpu_ns','observer_cpu_ns','combined_cpu_ns','main_callbacks','bpf_stats_before','bpf_stats_after']
    with (out/'rounds.csv').open('w',newline='') as stream:
        writer=csv.DictWriter(stream,keys,extrasaction='ignore');writer.writeheader();writer.writerows(rows)
    lines=['Current observer 57326bc, one service worker + one client, count+pairing only.',
           'All CPU values are ms. Main test CPU = service + clients + workload controller; observer separately retained.',
           'method | baseline test CPU | added test CPU | percent | delta MADN | main callbacks | read START | write START']
    for s in summaries:
        d=s['metrics']['test_cpu_ns'];c=s['counts']
        lines.append(f"{s['method']} | {d['baseline_ms']['median']:.2f} | {d['delta_ms']['median']:+.2f} | {d['overhead_pct']['median']:+.3f}% | {d['delta_ms']['madn']:.2f} | {s['callbacks']['median']:.0f} | {c['match_read_start']['median']:.0f} | {c['match_write_start']['median']:.0f}")
    (out/'SUMMARY.txt').write_text('\n'.join(lines)+'\n')

def measure(out,method,observe,repeat,requests,phase,expected_flag):
    label=f'{phase}-{repeat+1}-{method}-'+('on' if observe else 'off')
    directory=out/label;directory.mkdir()
    uid=int(os.environ.get('SUDO_UID',os.getuid()));gid=pwd.getpwuid(uid).pw_gid
    if os.geteuid()==0:os.chown(directory,uid,gid)
    if flag()!=expected_flag:raise RuntimeError('bpf_stats_enabled changed before '+label)
    parent,child=socket.socketpair();process=observer=None
    log=(directory/'controller.log').open('w')
    def ordinary_account():
        os.setsid()
        if os.geteuid()==0:
            os.setgroups([]);os.setgid(gid);os.setuid(uid)
    try:
        command=['/usr/bin/python3',str(HERE/'http/controller.py'),str(requests),str(CLIENTS),'16',str(directory)]
        process=subprocess.Popen(command,env=dict(os.environ,BENCH_PHASE_FD=str(child.fileno())),
                                 pass_fds=(child.fileno(),),stdout=log,stderr=log,preexec_fn=ordinary_account)
        child.close()
        ready=struct.unpack('=Iii32i',read_exact(parent,struct.calcsize('=Iii32i'),60))
        if ready[0]!=0x53544541 or ready[1]!=CLIENTS:raise RuntimeError('Bad ready payload')
        service_pid=ready[2];client_pids=list(ready[3:3+CLIENTS]);pids=[service_pid,process.pid]+client_pids
        if len(set(pids))!=CLIENTS+2:raise RuntimeError('Duplicate/absent workload process identity')
        clocks=[clock(pid) for pid in pids]
        backend=backends()['mmap/'+method]
        selected=Selection(backend,observe,'count','none',100000000,100,'both',None,backend.object,event_counts=True)
        observer=NativeObserver(selected,directory/'collector');observer.prepare();observer.start()
        before=[time.clock_gettime_ns(c) for c in clocks]
        observer_before=observer.cpu_ns();runner_before=time.process_time_ns();begin=time.monotonic_ns()
        parent.sendall(b'G')
        if read_exact(parent,1,600)!=b'D':raise RuntimeError('Bad completion payload')
        wall=time.monotonic_ns()-begin;runner_cpu=time.process_time_ns()-runner_before
        after=[time.clock_gettime_ns(c) for c in clocks];observer_cpu=observer.cpu_ns()-observer_before
        observer.stop();observation=observer.result();current_flag=flag()
        parent.sendall(b'F')
        code=process.wait(timeout=30);log.flush()
        if code:raise RuntimeError('HTTP controller failed; see '+str(directory/'controller.log'))
        lines=(directory/'controller.log').read_text().splitlines()
        work=json.loads(next(line for line in reversed(lines) if line.startswith('{')))
        if not work['verified'] or work['requests']!=requests or work['maps_created']!=requests:
            raise RuntimeError('HTTP request/mapping validation failed')
        if work['file_bytes_checked']!=requests*4194304 or work['files_checked']!=[requests//4]*4:
            raise RuntimeError('HTTP file work differs from the historical workload')
        if len(work['service']['worker_tids'])!=CLIENTS or len(work['client_results'])!=CLIENTS:
            raise RuntimeError('Not all service threads and client processes are represented')
        c=observation['counters']
        errors={k:c[k] for k in ERRORS if c[k]}
        if observation.get('retprobe_misses'):errors['retprobe_misses']=observation['retprobe_misses']
        if observation.get('mmap_cleanup_errors'):errors['mmap_cleanup_errors']=observation['mmap_cleanup_errors']
        if observation['error'] or observation['cleanup_error']:errors['observer_error']=observation['error'] or observation['cleanup_error']
        if observation['stack_entries']:errors['unexpected_stack_entries']=observation['stack_entries']
        delta=[y-x for x,y in zip(before,after)]
        if any(x<0 for x in delta) or delta[0]<=0 or sum(delta[2:])<=0:
            raise RuntimeError('Invalid process CPU clock deltas')
        if observe and c['match_write_start']<2*requests:
            errors['missing_request_write_entries']=c['match_write_start']
        if not observe and any(c.values()):errors['baseline_has_probe_counts']=True
        row=dict(label=label,method=method,observe=observe,repeat=repeat,phase=phase,requests=requests,clients=CLIENTS,
                 wall_ns=wall,service_cpu_ns=delta[0],controller_cpu_ns=delta[1],client_cpu_ns=sum(delta[2:]),
                 test_cpu_ns=sum(delta),observer_cpu_ns=observer_cpu,runner_cpu_ns=runner_cpu,
                 combined_cpu_ns=sum(delta)+observer_cpu+runner_cpu,process_pids=pids,
                 main_callbacks=sum(c[k] for k in KEYS),counters=c,errors=errors,
                 bpf_stats_before=expected_flag,bpf_stats_after=current_flag,
                 observation=observation,workload=work,command=command)
        dump(directory/'measurement.json',row)
        if current_flag!=expected_flag:raise RuntimeError('bpf_stats_enabled changed during '+label)
        if errors:raise RuntimeError('Collector validation failed: '+str(errors))
        for pid in pids:
            if Path(f'/proc/{pid}').exists():raise RuntimeError('Workload process did not exit: '+str(pid))
        status(f'{label}: CPU={sum(delta)/1e6:.2f}ms; wall={wall/1e9:.3f}s; callbacks={row["main_callbacks"]}; writes={c["match_write_start"]}')
        return row
    finally:
        stop(process)
        if observer:observer.close()
        parent.close();child.close();log.close()

def guard_active_experiments():
    for path in Path('/proc').glob('[0-9]*/cmdline'):
        if int(path.parent.name)==os.getpid():continue
        try:
            command=path.read_bytes().split(b'\0')
            if not command or not command[0]:continue
            names=[Path(os.fsdecode(arg)).name for arg in command if arg]
            if names[0].startswith('python') and 'run.py' in names:
                raise RuntimeError('Another experiment is running, PID '+path.parent.name)
            if names[0]=='observer' and b'--observe' in command and command[command.index(b'--observe')+1]==b'on':
                raise RuntimeError('Another observer is running, PID '+path.parent.name)
        except (OSError,IndexError):continue

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline-only',action='store_true')
    parser.add_argument('--smoke',action='store_true')
    parser.add_argument('--requests',type=int,default=6624)
    parser.add_argument('--repeats',type=int,default=3)
    args=parser.parse_args()
    if args.requests<4 or args.requests%4 or args.repeats<1:parser.error('Requests must be a positive multiple of 4')
    if not args.baseline_only and os.geteuid():raise SystemExit('Run with sudo to load BPF probes')
    guard_active_experiments()
    out=Path(tempfile.mkdtemp(prefix=time.strftime('results-%Y%m%d-%H%M%S-'),dir=HERE))
    uid=int(os.environ.get('SUDO_UID',os.getuid()));os.chown(out,uid,pwd.getpwuid(uid).pw_gid);out.chmod(0o755)
    expected=flag()
    dump(out/'metadata.json',dict(observer_commit='57326bc',kernel=os.uname().release,machine=os.uname().machine,
         bpf_stats_enabled=expected,requests=args.requests,clients=CLIENTS,warmup_per_client=16,repeats=args.repeats,
         collect='count',event_counts='on',timeout='none',scope='current unmodified host-wide observer',
         workload='historical HTTP checksum with one service worker and one client; unchanged file and request path',
         cpu_scope='process CPU clocks: service listener and sole worker + one client + controller; observer and runner separate',
         count_scope='host callback and host matching mmap_lock counts; not service-only PID filtering',
         flags_checked='before and after every run; never changed by experiment'))
    status('RESULTS: '+str(out));rows=[]
    try:
        if args.baseline_only:
            measure(out,'tracepoint',False,0,args.requests,'baseline-check',expected)
            dump(out/'completed.json',dict(checks='BASELINE_ONLY_PASS'));return
        for method in METHODS:
            measure(out,method,True,0,128,'validation',expected)
        if args.smoke:
            dump(out/'completed.json',dict(checks='SMOKE_PASS',methods=list(METHODS)));return
        rng=random.Random(2026102603);schedule=[]
        for repeat in range(args.repeats):
            order=list(METHODS);rng.shuffle(order)
            for method in order:
                arms=[False,True];rng.shuffle(arms);schedule.append(dict(repeat=repeat,method=method,order=arms))
        dump(out/'schedule.json',schedule)
        for block in schedule:
            for observe in block['order']:
                rows.append(measure(out,block['method'],observe,block['repeat'],args.requests,'timing',expected))
                dump(out/'rows.json',rows);summarize(out,rows)
        dump(out/'completed.json',dict(checks='PASS',formal_runs=len(rows),complete_pairs=len(METHODS)*args.repeats))
        status('CURRENT_HTTP_COMPLETE');print((out/'SUMMARY.txt').read_text())
    except BaseException as exc:
        dump(out/'failure.json',dict(error=repr(exc),completed_formal_runs=len(rows)))
        raise

if __name__=='__main__':main()
