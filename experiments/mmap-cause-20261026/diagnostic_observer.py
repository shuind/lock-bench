"""Export scoped component timings without modifying the native collector."""
import ctypes
from dataclasses import replace
import json
import os
from pathlib import Path
import struct
import subprocess
from program_stats import StatsObserver,read_fd

HERE=Path(__file__).resolve().parent
MODE='segments'
PAIRED=False
COMPONENTS=('front','identity_and_record','map_insert','finish')


class DiagnosticObserver(StatsObserver):
    def __init__(self,selection,directory,live=False):
        self.diag_fds={};self.root_pid=0;self.descendants=False;self.mode=MODE;self.paired=PAIRED
        self.runtime_identity=None
        super().__init__(replace(selection,object=HERE/(selection.backend.method+'-'+self.mode+'.bpf.o')),directory,live)

    def prepare(self):
        super().prepare();self.lib=ctypes.CDLL('libbpf.so.1',use_errno=True)
        self.lib.bpf_map_lookup_elem.argtypes=[ctypes.c_int,ctypes.c_void_p,ctypes.c_void_p]
        self.lib.bpf_map_update_elem.argtypes=[ctypes.c_int,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_ulonglong]
        self.cpus=self.lib.libbpf_num_possible_cpus()
        if self.cpus<1:raise RuntimeError('Cannot determine possible CPUs')
        seen=set()
        for p in Path(f'/proc/{self.process.pid}/fdinfo').iterdir():
            values=read_fd(p)
            if'map_id'not in values:continue
            identity=int(values['map_id'])
            if identity in seen:continue
            seen.add(identity)
            if values.get('value_size')not in ('24','72','256')or values.get('max_entries')not in('1','2'):continue
            info=json.loads(subprocess.check_output(['bpftool','-j','map','show','id',str(identity)],text=True))
            if isinstance(info,list):info=info[0]
            fd=self.lib.bpf_map_get_fd_by_id(identity)
            if fd<0:raise OSError(ctypes.get_errno(),'Cannot hold diagnostic map')
            if info['name']in('diag_control','diag_samples'):self.diag_fds[info['name']]=fd
            else:
                try:
                    if'rodata'in info['name']and values.get('value_size')=='72':
                        key=ctypes.c_uint32(0);raw=ctypes.create_string_buffer(72)
                        if not self.lib.bpf_map_lookup_elem(fd,ctypes.byref(key),raw):
                            ino=int.from_bytes(raw.raw[56:64],'little')
                            self.runtime_identity=dict(pid_namespace_ino=ino,id_helper='get_current_pid_tgid'if not ino else'get_ns_current_pid_tgid')
                finally:os.close(fd)
        if set(self.diag_fds)!={'diag_control','diag_samples'}:raise RuntimeError('Diagnostic maps missing')
        ready=self.directory.parent/'ready.json'
        if ready.is_file():self.set_profile_root(json.loads(ready.read_text())['pid'],False)

    def set_profile_root(self,pid,descendants):
        key=ctypes.c_uint32(0);value=ctypes.create_string_buffer(struct.pack('=IIIIQ',pid,int(descendants),int(self.paired),0,0))
        if self.lib.bpf_map_update_elem(self.diag_fds['diag_control'],ctypes.byref(key),value,0):
            raise OSError(ctypes.get_errno(),'Cannot set diagnostic root')
        self.root_pid=pid;self.descendants=descendants

    def scheduling(self):
        if not self.root_pid or self.descendants:return None
        values={};missing=[]
        for p in Path(f'/proc/{self.root_pid}/task').glob('[0-9]*'):
            try:
                metrics={}
                for line in (p/'sched').read_text().splitlines():
                    name,sep,value=line.partition(':');name=name.strip()
                    if sep and name in('se.nr_migrations','nr_switches','nr_voluntary_switches','nr_involuntary_switches'):
                        metrics[name]=int(value.strip())
                values[p.name]=metrics
            except(OSError,ValueError):missing.append(p.name)
        return dict(tasks=values,missing=missing)

    def start(self):
        super().start();self.scheduling_before=self.scheduling()

    def stop(self):
        scheduling_after=self.scheduling();super().stop()
        if not self.root_pid:raise RuntimeError('No diagnostic workload root configured')
        slots=[]
        for slot in range(2):
            key=ctypes.c_uint32(slot);value=ctypes.create_string_buffer(256*self.cpus)
            if self.lib.bpf_map_lookup_elem(self.diag_fds['diag_samples'],ctypes.byref(key),value):raise OSError(ctypes.get_errno(),'Cannot read diagnostic map')
            slots.append(list(struct.iter_unpack('='+'Q'*32,value.raw)))
        def decode(parts):
            sums=[sum(v[i]for v in parts)for i in range(32)];count=sums[0]
            components=[]
            for i,name in enumerate(COMPONENTS):
                components.append(dict(name=name,total_ns=sums[1+i],mean_ns=sums[1+i]/count if count else None,
                     min_ns=min((v[5+i]for v in parts if v[0]and v[5+i]),default=None),max_ns=max(v[9+i]for v in parts)))
            if self.mode=='segments'and sum(p['total_ns']for p in components)!=sums[13]:raise RuntimeError('Components do not sum to total')
            hist=[dict(bucket=name,calls=sums[17+i],elapsed_ns=sums[24+i])for i,name in enumerate(('<250ns','250-500ns','500-1000ns','1-2us','2-5us','5-10us','>=10us'))]
            if sum(h['calls']for h in hist)!=count or sum(h['elapsed_ns']for h in hist)!=sums[13]:raise RuntimeError('Histogram totals disagree')
            return dict(calls=count,total_ns=sums[13],mean_ns=sums[13]/count if count else None,
                 min_ns=min((v[14]for v in parts if v[0]),default=None),max_ns=max(v[15]for v in parts),
                 empty_reference_ns=sums[16]/count if count else None,max_ancestry=max(v[31]for v in parts),
                 components=components,histogram=hist,
                 cpu_calls=[sum(v[0]for i,v in enumerate(parts)if i%self.cpus==cpu)for cpu in range(self.cpus)])
        aggregate=decode(slots[0]+slots[1]);count=aggregate['calls']
        if not count:raise RuntimeError('No scoped mmap write entries')
        pairs=[decode(slot)for slot in slots]
        if self.paired:
            if pairs[0]['calls']!=pairs[1]['calls']:raise RuntimeError('Cold/warm call counts do not pair')
        elif pairs[1]['calls']:raise RuntimeError('Unexpected paired samples')
        c=self.value['counters']
        if count>c['match_write_start']:raise RuntimeError('Scoped entries exceed all-host matches')
        result=dict(mode=self.mode,root_pid=self.root_pid,descendants=self.descendants,**aggregate,
             paired=self.paired,pair_profiles=pairs,runtime_identity=self.runtime_identity,
             scheduling_before=self.scheduling_before,scheduling_after=scheduling_after,
             all_host_write_starts=c['match_write_start'],
             scope='HTTP service TGID, native root TGID, or make root plus descendants only; membership checked after final timestamp',
             interpretation='Temporary write START body instrumentation, component times include checkpoint overhead; total-only control and clock reference retained')
        (self.directory/'diagnostic.json').write_text(json.dumps(result,indent=2)+'\n')
        self.value['diagnostic']=result

    def close(self):
        try:super().close()
        finally:
            for fd in self.diag_fds.values():os.close(fd)
            self.diag_fds={}
