// SPDX-License-Identifier: GPL-2.0
// One record per lock/thread/mode. Count mode fills identity and pairing stage;
// state/stack modes add diagnostic times and a stack reference in the same value.
HASH(mm_records,struct mmap_key,struct record,8192);
// A local CO-RE flavor also compiles with headers from kernels before 5.11.
enum bpf_func_id___task { BPF_FUNC_get_current_task_btf___task=158 };
struct mmap_admission { struct mmap_key key; __u64 generation; };
static __always_inline void mm_cancel_key(struct counter_values *c,const struct mmap_key *key);
#ifdef OBSERVER_TIMER
HASH(mm_timers,struct mmap_key,struct timer_record,8192);
#endif
static __always_inline struct task_struct *mm_task(void) {
    // Newer kernels supply a verifier-trusted task pointer. CO-RE
    // removes this branch on kernels predating the helper (including 5.10).
    if(bpf_core_enum_value_exists(enum bpf_func_id___task,BPF_FUNC_get_current_task_btf___task)) {
        return bpf_get_current_task_btf();
    }
    return (void *)bpf_get_current_task();
}
static __always_inline struct mmap_key mm_key_task(__u64 sem,bool write,struct task_struct *task) {
    __u64 birth;
    if(bpf_core_enum_value_exists(enum bpf_func_id___task,BPF_FUNC_get_current_task_btf___task))birth=task->start_boottime;
    else birth=BPF_CORE_READ(task,start_boottime);
    return (struct mmap_key){.sem=sem,.task=(__u64)task,
        .task_start_ns=birth,.write=write};
}
static __always_inline struct mmap_key mm_key(__u64 sem,bool write) {
    return mm_key_task(sem,write,mm_task());
}
static __always_inline bool mm_current_task(__u64 sem,struct task_struct *task) {
    if(bpf_core_enum_value_exists(enum bpf_func_id___task,BPF_FUNC_get_current_task_btf___task)) {
        struct mm_struct *mm=task->mm;
        return mm && sem==(__u64)mm+bpf_core_field_offset(struct mm_struct,mmap_lock);
    }
    struct mm_struct *mm=BPF_CORE_READ(task,mm);
    return mm && sem==(__u64)mm+bpf_core_field_offset(struct mm_struct,mmap_lock);
}
static __always_inline bool mm_admit(bool write) {
    return cfg.enabled && cfg.admit && (settings.rw & (write ? 2 : 1));
}
static __always_inline struct record *mm_lookup(const struct mmap_key *key) {
    struct record *r=bpf_map_lookup_elem(&mm_records,key);
    return r && (r->stage==1 || r->stage==2) ? r : NULL;
}
static __always_inline bool mm_insert(struct counter_values *c,void *ctx,
        const struct mmap_key *key,bool held,__u64 *generation) {
    __u64 id=current_id();if(!id)return false;
    struct record value={.id=id,.stack_id=-1,.stage=held ? 2 : 1};
    if(settings.collect!=COLLECT_COUNT) {
        value.start_ns=bpf_ktime_get_ns();if(held)value.acquired_ns=value.start_ns;
    }
    // Publish a complete record once; no second lookup to fill its stack ID.
    if(settings.collect==COLLECT_STACK)value.stack_id=capture_stack(c,ctx);
    if(bpf_map_update_elem(&mm_records,key,&value,BPF_NOEXIST)) {
        count_diagnostic(c,PAIR_ERRORS);struct record *old=bpf_map_lookup_elem(&mm_records,key);
        if(old) {
            // Preserve the original evidence but quarantine this conflicting key.
            count_diagnostic(c,MM_DUPLICATE);if(old->stage!=3)count_diagnostic(c,MM_ABORTED);old->stage=3;
        }
        return false;
    }
    if(generation)*generation=value.start_ns;
    return true;
}
static __always_inline void mm_delete(struct counter_values *c,const struct mmap_key *key) {
    if(bpf_map_delete_elem(&mm_records,key))count_diagnostic(c,PAIR_ERRORS);
}
static __always_inline bool mm_start_task(struct counter_values *c,void *ctx,__u64 sem,bool write,bool identified,
        struct task_struct *task,struct mmap_admission *admission) {
    if(!cfg.enabled)return false;
    count(c,write ? TOTAL_WRITE_START : TOTAL_READ_START);
    if(!mm_admit(write))return false;
    if(!task)task=mm_task();
    // Return the task even on a rejected lock, for kretprobe parameter pairing.
    if(admission)admission->key.task=(__u64)task;
    if(!identified && !mm_current_task(sem,task))return false;
    struct mmap_key key=mm_key_task(sem,write,task);
    if(!mm_insert(c,ctx,&key,false,admission ? &admission->generation : NULL))return false;
    if(admission)admission->key=key;
    count(c,write ? MATCH_WRITE_START : MATCH_READ_START);return true;
}
static __always_inline bool mm_start_key(struct counter_values *c,void *ctx,__u64 sem,bool write,bool identified,
        struct mmap_admission *admission) {
    return mm_start_task(c,ctx,sem,write,identified,NULL,admission);
}
static __always_inline bool mm_start(struct counter_values *c,void *ctx,__u64 sem,bool write,bool identified) {
    return mm_start_key(c,ctx,sem,write,identified,NULL);
}
static __always_inline void mm_return_key(struct counter_values *c,const struct mmap_key *key,bool success,
        struct task_struct *task) {
    bool write=key->write;struct record *r=mm_lookup(key);
    // mmap_write_downgrade emits read ACQUIRE before downgrade_write executes.
    bool implicit=false;
#ifdef OBSERVER_MMAP_EVENTS
    if(!r && !write && success && (settings.rw&1)) {
        struct mmap_key wk=*key;wk.write=1;implicit=mm_lookup(&wk)!=NULL;
    }
#endif
    if(!r && !implicit)return;
    if(!mm_current_task(key->sem,task))count_diagnostic(c,MM_RETURN_OLD);
    if(success)count(c,write ? MATCH_WRITE_ACQUIRE : MATCH_READ_ACQUIRE);
    else count(c,write ? MATCH_WRITE_FAILED : MATCH_READ_FAILED);
    if(!r)return;
    if(!success) {mm_delete(c,key);return;}
    if(settings.collect!=COLLECT_COUNT)r->acquired_ns=bpf_ktime_get_ns();r->stage=2;
}
static __always_inline void mm_return(struct counter_values *c,__u64 sem,bool write,bool success) {
    if(!cfg.enabled)return;
    count(c,write ? TOTAL_WRITE_RETURN : TOTAL_READ_RETURN);
    if(!(settings.rw & (write ? 2 : 1)))return;
    struct task_struct *task=mm_task();
    struct mmap_key key=mm_key_task(sem,write,task);
    if(!success)mm_cancel_key(c,&key);
    mm_return_key(c,&key,success,task);
}
static __always_inline void mm_release(struct counter_values *c,__u64 sem,bool write) {
    if(!cfg.enabled)return;
    count(c,write ? TOTAL_WRITE_RELEASE : TOTAL_READ_RELEASE);
    if(!(settings.rw & (write ? 2 : 1)))return;
    struct task_struct *task=mm_task();
    struct mmap_key key=mm_key_task(sem,write,task);mm_cancel_key(c,&key);
    if(!mm_lookup(&key))return;
    if(!mm_current_task(sem,task))count_diagnostic(c,MM_RELEASE_OLD);
    count(c,write ? MATCH_WRITE_RELEASE : MATCH_READ_RELEASE);mm_delete(c,&key);
}
static __always_inline bool mm_downgrade_key(struct counter_values *c,void *ctx,__u64 sem,bool implicit,
        struct mmap_admission *admission) {
    if(!cfg.enabled)return false;
    count(c,TOTAL_DOWNGRADE);
    struct mmap_key key=mm_key(sem,true);mm_cancel_key(c,&key);
    if(!mm_lookup(&key))return false;
    count(c,MATCH_DOWNGRADE);count(c,MATCH_WRITE_RELEASE);
    // Retire the ended write phase first, also freeing capacity for the read key.
    mm_delete(c,&key);if(!(settings.rw&1))return false;
    key.write=0;if(!mm_insert(c,ctx,&key,true,admission ? &admission->generation : NULL))return false;
    if(admission)admission->key=key;
    if(implicit)count(c,MATCH_READ_ACQUIRE);return true;
}
static __always_inline bool mm_downgrade(struct counter_values *c,void *ctx,__u64 sem,bool implicit) {
    return mm_downgrade_key(c,ctx,sem,implicit,NULL);
}
#ifdef OBSERVER_TIMER
static int mm_timer_cb(void *map,struct mmap_key *key,struct timer_record *timer) {
    struct counter_values *c=counts_get();
    if(!cfg.enabled)return 0;count(c,TIMER_FIRED);
    struct record *r=bpf_map_lookup_elem(&mm_records,key);
    if(!r || r->start_ns!=timer->generation)return 0;
    struct event *e=bpf_ringbuf_reserve(&events,sizeof(*e),0);
    if(!e) {count_diagnostic(c,RING_DROPPED);return 0;}
    *e=(struct event){.state=*r,.now_ns=bpf_ktime_get_ns(),
        .lock_kind=key->write ? 2 : 1,.lock_addr=key->sem};
    bpf_ringbuf_submit(e,0);count(c,RING_SENT);return 0;
}
static __always_inline void mm_arm(struct counter_values *c,const struct mmap_admission *admission) {
    if(!with_timer())return;
    // The successful insertion already produced both the key and generation.
    // Re-reading current task or looking the record up adds no information.
    const struct mmap_key *key=&admission->key;
    struct timer_record zero={.generation=admission->generation};
    if(bpf_map_update_elem(&mm_timers,key,&zero,BPF_NOEXIST)) {count_diagnostic(c,TIMER_ERRORS);return;}
    struct timer_record *t=bpf_map_lookup_elem(&mm_timers,key);
    if(!t || bpf_timer_init(&t->timer,&mm_timers,1) || bpf_timer_set_callback(&t->timer,mm_timer_cb)) {count_diagnostic(c,TIMER_ERRORS);return;}
    t->initialized=1;
    if(bpf_timer_start(&t->timer,settings.threshold_ns,0))count_diagnostic(c,TIMER_ERRORS);else count(c,TIMER_ARMED);
}
static __always_inline void mm_cancel_key(struct counter_values *c,const struct mmap_key *key) {
    if(!with_timer())return;
    struct timer_record *t=bpf_map_lookup_elem(&mm_timers,key);
    if(!t)return;
    if(t->initialized) {
        if(bpf_timer_cancel(&t->timer)<0)count_diagnostic(c,TIMER_ERRORS);else count(c,TIMER_CANCELLED);
    }
    if(bpf_map_delete_elem(&mm_timers,key))count_diagnostic(c,TIMER_ERRORS);
}
#else
static __always_inline void mm_arm(struct counter_values *c,const struct mmap_admission *admission) {}
static __always_inline void mm_cancel_key(struct counter_values *c,const struct mmap_key *key) {}
#endif
