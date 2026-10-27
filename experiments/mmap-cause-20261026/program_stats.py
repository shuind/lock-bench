"""Read each program held by the selected native collector; leave probes unchanged."""
import json
from pathlib import Path
import subprocess
import time
from observer.native import NativeObserver

FUNCTIONS=('down_read','down_read_killable','down_read_trylock',
           'down_write','down_write_killable','down_write_trylock')


def describe(name,method):
    if name=='mx_exit':return dict(stage='cleanup',hook='tp/sched/sched_process_exit',rw=None)
    if name.endswith('_downgrade'):
        return dict(stage='downgrade',hook=('fentry/' if method=='fentry' else 'kprobe/')+'downgrade_write',rw='write_to_read')
    if method in ('tracepoint','raw'):
        stage={'start':'start','return':'returned','release':'release'}[name.split('_',1)[1]]
        event={'start':'start_locking','returned':'acquire_returned','release':'released'}[stage]
        return dict(stage=stage,hook=('tp/mmap_lock/mmap_lock_' if method=='tracepoint' else 'raw_tp/mmap_lock_')+event,rw='both')
    if '_begin_' in name or '_ret_' in name:
        index=int(name.rsplit('_',1)[1]);stage='start' if '_begin_' in name else 'returned'
        prefix=('fentry/' if stage=='start' else 'fexit/') if method=='fentry' else ('kprobe/' if stage=='start' else 'kretprobe/')
        return dict(stage=stage,hook=prefix+FUNCTIONS[index],rw='read' if index<3 else 'write')
    if name.endswith('_read_up') or name.endswith('_write_up'):
        rw='read' if name.endswith('_read_up') else 'write'
        return dict(stage='release',hook=('fentry/' if method=='fentry' else 'kprobe/')+'up_'+rw,rw=rw)
    raise ValueError('Unmapped program: '+name)


def read_fd(path):
    return {key:value.strip() for line in path.read_text().splitlines()
            for key,sep,value in [line.partition(':')] if sep}


class StatsObserver(NativeObserver):
    def prepare(self):
        super().prepare()
        expected=set(self.selection.backend.programs)
        self.stats_fds={};seen=set()
        for path in sorted(Path(f'/proc/{self.process.pid}/fdinfo').iterdir(),key=lambda p:int(p.name)):
            fields=read_fd(path)
            if not {'prog_type','prog_id','run_cnt','run_time_ns'}<=fields.keys():continue
            identity=int(fields['prog_id'])
            if identity in seen:continue
            seen.add(identity)
            info=json.loads(subprocess.check_output(['bpftool','-j','prog','show','id',str(identity)],text=True))
            if isinstance(info,list):
                if len(info)!=1:raise RuntimeError('Ambiguous BPF program identity')
                info=info[0]
            name=info['name']
            if name not in expected:raise RuntimeError('Unexpected owned program: '+name)
            if name in self.stats_fds:raise RuntimeError('Duplicate owned program: '+name)
            self.stats_fds[name]=(path,identity)
        if set(self.stats_fds)!=expected:
            raise RuntimeError(f'Program set differs from backend descriptor: {set(self.stats_fds)} != {expected}')

    def stats_snapshot(self):
        values={}
        for name,(path,identity) in sorted(self.stats_fds.items()):
            fields=read_fd(path)
            if int(fields['prog_id'])!=identity:raise RuntimeError('Collector program FD identity changed')
            values[name]={key:int(fields[key]) for key in ('prog_id','run_cnt','run_time_ns','recursion_misses')}
            values[name]['sample_monotonic_ns']=time.monotonic_ns()
        return values

    def start(self):
        super().start()
        self.stats_before=self.stats_snapshot()

    def stop(self):
        after=self.stats_snapshot()
        super().stop()
        programs=[]
        for name,before in self.stats_before.items():
            end=after[name]
            calls=end['run_cnt']-before['run_cnt'];runtime=end['run_time_ns']-before['run_time_ns']
            missed=end['recursion_misses']-before['recursion_misses']
            if calls<0 or runtime<0 or missed:raise RuntimeError('Invalid/incomplete kernel BPF statistics')
            if not calls and runtime:raise RuntimeError('Runtime without any recorded invocation')
            programs.append(dict(name=name,id=end['prog_id'],run_cnt=calls,run_time_ns=runtime,
                                 mean_ns=runtime/calls if calls else None,recursion_misses=missed,
                                 **describe(name,self.selection.backend.method)))
        if not sum(p['run_cnt'] for p in programs) or not sum(p['run_time_ns'] for p in programs):
            raise RuntimeError('BPF runtime statistics are inactive')
        stats=dict(before=self.stats_before,after=after,programs=programs,
                   backend=self.selection.backend.id,
                   scope='Only the selected collector owns these program IDs; invocations include all host CPUs/tasks and rejected operations',
                   boundary='Per-program snapshots around workload, before drain/export; not atomic across programs',
                   interpretation='Kernel-accounted BPF mean execution time; not complete hook overhead or individual invocation percentiles')
        (self.directory/'program-stats.json').write_text(json.dumps(stats,indent=2)+'\n')
        self.value['kernel_program_stats']=stats
