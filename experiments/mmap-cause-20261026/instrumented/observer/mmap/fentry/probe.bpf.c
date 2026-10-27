// SPDX-License-Identifier: GPL-2.0
#include "../../common/base.bpf.h"
#include "../state.bpf.h"
// Private experiment: measurements never alter production observer sources.
struct diagnostic_control { __u32 root_tgid, descendants, paired, reserved; __u64 sequence; };
struct diagnostic_sample { __u64 values[32]; };
struct diagnostic_marks { __u64 time[5]; };
struct { __uint(type,BPF_MAP_TYPE_ARRAY); __uint(max_entries,1);
    __type(key,__u32); __type(value,struct diagnostic_control); } diag_control SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_PERCPU_ARRAY); __uint(max_entries,2);
    __type(key,__u32); __type(value,struct diagnostic_sample); } diag_samples SEC(".maps");

static __always_inline __u32 diagnostic_tgid(struct task_struct *task) {
    if(!settings.pid_ns_ino)return BPF_CORE_READ(task,tgid);
    struct task_struct *leader=BPF_CORE_READ(task,group_leader);
    struct pid *pid=BPF_CORE_READ(leader,thread_pid);
    if(!pid)return 0;
    __u32 level=BPF_CORE_READ(pid,level);
    for(__u32 i=0;i<32;i++) {
        if(i>level)return 0;
        struct upid item={0};
        const void *address=(const char *)pid+bpf_core_field_offset(struct pid,numbers)+i*sizeof(item);
        if(bpf_probe_read_kernel(&item,sizeof(item),address))return 0;
        if(item.ns && BPF_CORE_READ(item.ns,ns.inum)==settings.pid_ns_ino)return item.nr;
    }
    return 0;
}

static __always_inline bool diagnostic_scope(__u32 *depth,__u32 *slot) {
    __u32 zero=0;struct diagnostic_control *control=bpf_map_lookup_elem(&diag_control,&zero);
    if(!control || !control->root_tgid)return false;
    struct task_struct *task=mm_task();
    for(__u32 i=0;i<32;i++) {
        __u32 tgid=diagnostic_tgid(task);
        if(tgid==control->root_tgid) {*depth=i;*slot=control->paired ? (control->sequence++ & 1) : 0;return true;}
        if(!control->descendants || !tgid)return false;
        struct task_struct *parent=BPF_CORE_READ(task,real_parent);
        if(!parent || parent==task)return false;
        task=parent;
    }
    return false;
}

static __always_inline void diagnostic_finish(const struct diagnostic_marks *m) {
    __u32 depth=0,slot=0;
    // Resolve experiment membership AFTER the final timestamp. The original
    // collector still observes the whole host; only diagnostic export is scoped.
    if(!m->time[0] || !diagnostic_scope(&depth,&slot))return;
    struct diagnostic_sample *sample=bpf_map_lookup_elem(&diag_samples,&slot);
    if(!sample)return;
    __u64 *v=sample->values,total=m->time[4]-m->time[0];
    v[0]++;v[13]+=total;if(!v[14] || total<v[14])v[14]=total;if(total>v[15])v[15]=total;
#if !DIAG_TOTAL_ONLY
    for(int i=0;i<4;i++) {
        __u64 ns=m->time[i+1]-m->time[i];v[1+i]+=ns;
        if(!v[5+i] || ns<v[5+i])v[5+i]=ns;if(ns>v[9+i])v[9+i]=ns;
    }
#endif
    __u32 bucket=total<250 ? 0 : total<500 ? 1 : total<1000 ? 2 : total<2000 ? 3 : total<5000 ? 4 : total<10000 ? 5 : 6;
    v[17+bucket]++;v[24+bucket]+=total;
    if(depth>v[31])v[31]=depth;
    __u64 a=bpf_ktime_get_ns(),b=bpf_ktime_get_ns();v[16]+=b-a;
}

static __always_inline bool diagnostic_start(struct counter_values *c,void *ctx,__u64 sem,bool identified,struct diagnostic_marks *m) {
#if DIAG_TOTAL_ONLY
    bool accepted=mm_start(c,ctx,sem,true,identified);
    m->time[4]=bpf_ktime_get_ns();return accepted;
#else
    if(!cfg.enabled)return false;
    count(c,TOTAL_WRITE_START);
    if(!mm_admit(true))return false;
    struct task_struct *task=mm_task();
    if(!identified && !mm_current_task(sem,task))return false;
    struct mmap_key key=mm_key_task(sem,true,task);
    m->time[1]=bpf_ktime_get_ns();
    __u64 id=current_id();if(!id)return false;
    struct record value={.id=id,.stack_id=-1,.stage=1};
    if(settings.collect!=COLLECT_COUNT)value.start_ns=bpf_ktime_get_ns();
    if(settings.collect==COLLECT_STACK)value.stack_id=capture_stack(c,ctx);
    m->time[2]=bpf_ktime_get_ns();
    int error=bpf_map_update_elem(&mm_records,&key,&value,BPF_NOEXIST);
    m->time[3]=bpf_ktime_get_ns();
    if(error) {
        count_diagnostic(c,PAIR_ERRORS);struct record *old=bpf_map_lookup_elem(&mm_records,&key);
        if(old) {count_diagnostic(c,MM_DUPLICATE);if(old->stage!=3)count_diagnostic(c,MM_ABORTED);old->stage=3;}
        return false;
    }
    count(c,MATCH_WRITE_START);m->time[4]=bpf_ktime_get_ns();return true;
#endif
}

static __always_inline void on_start(struct counter_values *c,void *ctx,__u64 sem,bool write) {
#ifdef OBSERVER_TIMER
    struct mmap_admission a={0};if(mm_start_key(c,ctx,sem,write,false,&a))mm_arm(c,&a);
#else
    mm_start(c,ctx,sem,write,false);
#endif
}
static __always_inline void on_downgrade(struct counter_values *c,void *ctx,__u64 sem) {
#ifdef OBSERVER_TIMER
    struct mmap_admission a={0};if(mm_downgrade_key(c,ctx,sem,true,&a))mm_arm(c,&a);
#else
    mm_downgrade(c,ctx,sem,true);
#endif
}
#define ENTRY(id,fn,write) \
SEC("fentry/" #fn) int BPF_PROG(mf_begin_##id,struct rw_semaphore *sem) {if(id!=4) {struct counter_values *c=counts_get();on_start(c,ctx,(__u64)sem,write);return 0;}     struct diagnostic_marks mark={0};mark.time[0]=bpf_ktime_get_ns();struct counter_values *c=counts_get();     bool accepted=diagnostic_start(c,ctx,(__u64)sem,false,&mark);if(accepted)diagnostic_finish(&mark);return 0;}
#define RETURN_VOID(id,fn,write) \
SEC("fexit/" #fn) int BPF_PROG(mf_ret_##id,struct rw_semaphore *sem) {struct counter_values *c=counts_get();mm_return(c,(__u64)sem,write,true);return 0;}
#define RETURN_INT(id,fn,write,success) \
SEC("fexit/" #fn) int BPF_PROG(mf_ret_##id,struct rw_semaphore *sem,int ret) {struct counter_values *c=counts_get();mm_return(c,(__u64)sem,write,success);return 0;}
ENTRY(0,down_read,false)
RETURN_VOID(0,down_read,false)
ENTRY(1,down_read_killable,false)
RETURN_INT(1,down_read_killable,false,ret==0)
ENTRY(2,down_read_trylock,false)
RETURN_INT(2,down_read_trylock,false,ret!=0)
ENTRY(3,down_write,true)
RETURN_VOID(3,down_write,true)
ENTRY(4,down_write_killable,true)
RETURN_INT(4,down_write_killable,true,ret==0)
ENTRY(5,down_write_trylock,true)
RETURN_INT(5,down_write_trylock,true,ret!=0)
SEC("fentry/up_read") int BPF_PROG(mf_read_up,struct rw_semaphore *sem) {struct counter_values *c=counts_get();mm_release(c,(__u64)sem,false);return 0;}
SEC("fentry/up_write") int BPF_PROG(mf_write_up,struct rw_semaphore *sem) {struct counter_values *c=counts_get();mm_release(c,(__u64)sem,true);return 0;}
SEC("fentry/downgrade_write") int BPF_PROG(mf_downgrade,struct rw_semaphore *sem) {struct counter_values *c=counts_get();on_downgrade(c,ctx,(__u64)sem);return 0;}


char LICENSE[] SEC("license")="GPL";
