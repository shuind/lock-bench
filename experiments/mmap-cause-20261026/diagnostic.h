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
