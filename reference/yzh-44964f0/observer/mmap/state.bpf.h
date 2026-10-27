// SPDX-License-Identifier: GPL-2.0
// One record per lock/thread/mode. Count mode fills identity and pairing stage;
// state/stack modes add diagnostic times and a stack reference in the same value.
HASH(mm_records,struct mmap_key,struct record,8192);
#ifdef OBSERVER_TIMER
HASH(mm_timers,struct mmap_key,struct timer_record,8192);
#endif
#ifdef OBSERVER_RETURNS
struct mmap_call_key { __u64 task; __u32 kind,pad; };
HASH(mm_calls,struct mmap_call_key,struct pending,8192);
#endif
static __always_inline struct mmap_key mm_key(__u64 sem,bool write) {
    struct task_struct *task=(void *)bpf_get_current_task();
    return (struct mmap_key){.sem=sem,.task=(__u64)task,
        .task_start_ns=BPF_CORE_READ(task,start_boottime),.write=write};
}
static __always_inline bool mm_current(__u64 sem) {
    struct task_struct *task=(void *)bpf_get_current_task();
    struct mm_struct *mm=BPF_CORE_READ(task,mm);
    return mm && sem==(__u64)mm+bpf_core_field_offset(struct mm_struct,mmap_lock);
}
static __always_inline bool mm_admit(__u64 sem,bool write,bool identified) {
    return cfg.enabled && cfg.admit && (cfg.rw & (write ? 2 : 1)) && (identified || mm_current(sem));
}
static __always_inline struct record *mm_lookup(const struct mmap_key *key) {
    struct record *r=bpf_map_lookup_elem(&mm_records,key);
    return r && (r->stage==1 || r->stage==2) ? r : NULL;
}
static __always_inline bool mm_insert(struct counter_values *c,void *ctx,
        const struct mmap_key *key,bool held) {
    __u64 id=current_id();if(!id)return false;
    struct record value={.id=id,.stack_id=-1,.stage=held ? 2 : 1};
    if(cfg.collect!=COLLECT_COUNT) {
        value.start_ns=bpf_ktime_get_ns();if(held)value.acquired_ns=value.start_ns;
    }
    if(bpf_map_update_elem(&mm_records,key,&value,BPF_NOEXIST)) {
        count(c,PAIR_ERRORS);struct record *old=bpf_map_lookup_elem(&mm_records,key);
        if(old) {
            // Preserve the original evidence but quarantine this conflicting key.
            count(c,MM_DUPLICATE);if(old->stage!=3)count(c,MM_ABORTED);old->stage=3;
        }
        return false;
    }
    if(cfg.collect==COLLECT_STACK) {
        int id=capture_stack(c,ctx);struct record *r=bpf_map_lookup_elem(&mm_records,key);
        if(r)r->stack_id=id;else count(c,STATE_ERRORS);
    }
    return true;
}
static __always_inline void mm_delete(struct counter_values *c,const struct mmap_key *key) {
    if(bpf_map_delete_elem(&mm_records,key))count(c,PAIR_ERRORS);
}
static __always_inline bool mm_start(struct counter_values *c,void *ctx,__u64 sem,bool write,bool identified) {
    count(c,write ? TOTAL_WRITE_START : TOTAL_READ_START);
    if(!mm_admit(sem,write,identified))return false;
    struct mmap_key key=mm_key(sem,write);
    if(!mm_insert(c,ctx,&key,false))return false;
    count(c,write ? MATCH_WRITE_START : MATCH_READ_START);return true;
}
static __always_inline void mm_return(struct counter_values *c,__u64 sem,bool write,bool success) {
    count(c,write ? TOTAL_WRITE_RETURN : TOTAL_READ_RETURN);
    struct mmap_key key=mm_key(sem,write);struct record *r=mm_lookup(&key);
    // mmap_write_downgrade emits read ACQUIRE before downgrade_write executes.
    bool implicit=false;
    if(!r && !write && success && (cfg.rw&1)) {
        struct mmap_key wk=key;wk.write=1;implicit=mm_lookup(&wk)!=NULL;
    }
    if(!r && !implicit)return;
    if(!mm_current(sem))count(c,MM_RETURN_OLD);
    if(success)count(c,write ? MATCH_WRITE_ACQUIRE : MATCH_READ_ACQUIRE);
    else count(c,write ? MATCH_WRITE_FAILED : MATCH_READ_FAILED);
    if(!r)return;
    if(!success) {mm_delete(c,&key);return;}
    if(cfg.collect!=COLLECT_COUNT)r->acquired_ns=bpf_ktime_get_ns();r->stage=2;
}
static __always_inline void mm_release(struct counter_values *c,__u64 sem,bool write) {
    count(c,write ? TOTAL_WRITE_RELEASE : TOTAL_READ_RELEASE);
    struct mmap_key key=mm_key(sem,write);if(!mm_lookup(&key))return;
    if(!mm_current(sem))count(c,MM_RELEASE_OLD);
    count(c,write ? MATCH_WRITE_RELEASE : MATCH_READ_RELEASE);mm_delete(c,&key);
}
static __always_inline bool mm_downgrade(struct counter_values *c,void *ctx,__u64 sem,bool implicit) {
    count(c,TOTAL_DOWNGRADE);
    struct mmap_key key=mm_key(sem,true);if(!mm_lookup(&key))return false;
    count(c,MATCH_DOWNGRADE);count(c,MATCH_WRITE_RELEASE);
    // Retire the ended write phase first, also freeing capacity for the read key.
    mm_delete(c,&key);if(!(cfg.rw&1))return false;
    key.write=0;if(!mm_insert(c,ctx,&key,true))return false;
    if(implicit)count(c,MATCH_READ_ACQUIRE);return true;
}
#ifdef OBSERVER_TIMER
static int mm_timer_cb(void *map,struct mmap_key *key,struct timer_record *timer) {
    struct counter_values *c=counts_get();
    if(!cfg.enabled)return 0;count(c,TIMER_FIRED);
    struct record *r=bpf_map_lookup_elem(&mm_records,key);
    if(!r || r->start_ns!=timer->generation)return 0;
    struct event *e=bpf_ringbuf_reserve(&events,sizeof(*e),0);
    if(!e) {count(c,RING_DROPPED);return 0;}
    *e=(struct event){.state=*r,.now_ns=bpf_ktime_get_ns(),
        .lock_kind=key->write ? 2 : 1,.lock_addr=key->sem};
    bpf_ringbuf_submit(e,0);count(c,RING_SENT);return 0;
}
static __always_inline void mm_arm(struct counter_values *c,__u64 sem,bool write) {
    if(!with_timer())return;
    struct mmap_key key=mm_key(sem,write);struct record *r=mm_lookup(&key);
    if(!r) {count(c,TIMER_ERRORS);return;}
    struct timer_record zero={.generation=r->start_ns};
    if(bpf_map_update_elem(&mm_timers,&key,&zero,BPF_NOEXIST)) {count(c,TIMER_ERRORS);return;}
    struct timer_record *t=bpf_map_lookup_elem(&mm_timers,&key);
    if(!t || bpf_timer_init(&t->timer,&mm_timers,1) || bpf_timer_set_callback(&t->timer,mm_timer_cb)) {count(c,TIMER_ERRORS);return;}
    t->initialized=1;
    if(bpf_timer_start(&t->timer,cfg.threshold_ns,0))count(c,TIMER_ERRORS);else count(c,TIMER_ARMED);
}
static __always_inline void mm_cancel(struct counter_values *c,__u64 sem,bool write) {
    if(!with_timer())return;
    struct mmap_key key=mm_key(sem,write);struct timer_record *t=bpf_map_lookup_elem(&mm_timers,&key);
    if(!t)return;
    if(t->initialized) {
        if(bpf_timer_cancel(&t->timer)<0)count(c,TIMER_ERRORS);else count(c,TIMER_CANCELLED);
    }
    if(bpf_map_delete_elem(&mm_timers,&key))count(c,TIMER_ERRORS);
}
#else
static __always_inline void mm_arm(struct counter_values *c,__u64 sem,bool write) {}
static __always_inline void mm_cancel(struct counter_values *c,__u64 sem,bool write) {}
#endif
#ifdef OBSERVER_RETURNS
static __always_inline void mm_kstart(struct counter_values *c,void *ctx,__u64 sem,bool write,__u32 kind) {
    bool accepted=mm_start(c,ctx,sem,write,false);struct mmap_call_key key={.task=token(),.kind=kind};
    struct pending *p=bpf_map_lookup_elem(&mm_calls,&key);
    if(!accepted && !p)return;
    if(!p) {
        struct pending zero={0};if(bpf_map_update_elem(&mm_calls,&key,&zero,BPF_NOEXIST)) {count(c,PAIR_ERRORS);return;}
        p=bpf_map_lookup_elem(&mm_calls,&key);
    }
    if(!p || p->count>=4) {count(c,PAIR_ERRORS);return;}
    __u32 i=p->count;p->sem[i]=sem;p->accepted[i]=accepted;p->count=i+1;
}
static __always_inline void mm_kreturn(struct counter_values *c,bool write,__u32 kind,bool success) {
    struct mmap_call_key key={.task=token(),.kind=kind};struct pending *p=bpf_map_lookup_elem(&mm_calls,&key);
    if(!p || !p->count) {count(c,write ? TOTAL_WRITE_RETURN : TOTAL_READ_RETURN);return;}
    __u32 i=p->count-1;if(i>=4) {count(c,PAIR_ERRORS);return;}
    if(p->accepted[i])mm_return(c,p->sem[i],write,success);
    else count(c,write ? TOTAL_WRITE_RETURN : TOTAL_READ_RETURN);
    p->count=i;if(!i && bpf_map_delete_elem(&mm_calls,&key))count(c,PAIR_ERRORS);
}
#endif
