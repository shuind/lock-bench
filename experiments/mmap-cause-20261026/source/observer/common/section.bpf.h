// Shared state machine for one admitted section, used by cgroup and fork.
// The record is also the admission token. Count mode needs only its identity.
HASH(states,struct trace_key,struct record,8192);
struct section_admission { struct trace_key key; __u64 generation; };
#ifdef OBSERVER_TIMER
HASH(timers,struct trace_key,struct timer_record,8192);
#endif
#ifdef OBSERVER_RETURNS
HASH(inflight,__u64,struct pending,8192);
#endif
// Retain object identification, but accept every process on the host.
static __always_inline bool admit(__u64 sem) {
    return cfg.enabled && cfg.admit && (!sem || sem==settings.target_lock);
}
static __always_inline bool start_key(struct counter_values *c,void *ctx,__u64 sem,struct section_admission *admission) {
    if(!cfg.enabled)return false;
    count(c,TOTAL_START);if(!admit(sem))return false;
    struct trace_key key=key_for(sem);
    struct record r={.id=current_id(),.stack_id=-1,.stage=1};if(!r.id)return false;
    if(settings.collect!=COLLECT_COUNT) {
        r.start_ns=bpf_ktime_get_ns();
        if(settings.collect==COLLECT_STACK) {
            r.stack_id=capture_stack(c,ctx);
        }
    }
    if(bpf_map_update_elem(&states,&key,&r,BPF_NOEXIST)) {count_diagnostic(c,PAIR_ERRORS);return false;}
    if(admission)*admission=(struct section_admission){.key=key,.generation=r.start_ns};
    count(c,MATCH_START);
    return true;
}
static __always_inline bool start(struct counter_values *c,void *ctx,__u64 sem) {
    return start_key(c,ctx,sem,NULL);
}
static __always_inline void acquired(struct counter_values *c,__u64 sem) {
    if(!cfg.enabled)return;
    count(c,TOTAL_ACQUIRE);if(sem && sem!=settings.target_lock)return;
    struct trace_key key=key_for(sem);struct record *r=bpf_map_lookup_elem(&states,&key);
    if(!r)return;
    count(c,MATCH_ACQUIRE);
    if(settings.collect!=COLLECT_COUNT) {
        r->acquired_ns=bpf_ktime_get_ns();r->stage=2;
    }
}
static __always_inline void end(struct counter_values *c,__u64 sem) {
    if(!cfg.enabled)return;
    count(c,TOTAL_END);if(sem && sem!=settings.target_lock)return;
    struct trace_key key=key_for(sem);
    // A successful delete both confirms admission and retires the operation.
    if(bpf_map_delete_elem(&states,&key))return;
    count(c,MATCH_END);
}

#ifdef OBSERVER_TIMER
static int timer_cb(void *map,struct trace_key *key,struct timer_record *timer) {
    struct counter_values *c=counts_get();
    if(!cfg.enabled)return 0;
    count(c,TIMER_FIRED);
    struct record *r=bpf_map_lookup_elem(&states,key);
    if(!r || r->start_ns!=timer->generation)return 0;
    struct event *e=bpf_ringbuf_reserve(&events,sizeof(*e),0);
    if(!e) {count_diagnostic(c,RING_DROPPED);return 0;}
    *e=(struct event){.state=*r,.now_ns=bpf_ktime_get_ns(),.lock_addr=key->sem};
    bpf_ringbuf_submit(e,0);count(c,RING_SENT);return 0;
}
static __always_inline void arm(struct counter_values *c,const struct section_admission *admission) {
    if(!with_timer())return;
    const struct trace_key *key=&admission->key;
    struct timer_record zero={.generation=admission->generation};
    if(bpf_map_update_elem(&timers,key,&zero,BPF_NOEXIST)) {count_diagnostic(c,TIMER_ERRORS);return;}
    struct timer_record *t=bpf_map_lookup_elem(&timers,key);
    if(!t || bpf_timer_init(&t->timer,&timers,1) || bpf_timer_set_callback(&t->timer,timer_cb)) {count_diagnostic(c,TIMER_ERRORS);return;}
    t->initialized=1;
    if(bpf_timer_start(&t->timer,settings.threshold_ns,0))count_diagnostic(c,TIMER_ERRORS);else count(c,TIMER_ARMED);
}
static __always_inline void cancel(struct counter_values *c,__u64 sem) {
    if(!with_timer())return;
    struct trace_key key=key_for(sem);struct timer_record *t=bpf_map_lookup_elem(&timers,&key);
    if(!t)return;
    if(t->initialized) {
        if(bpf_timer_cancel(&t->timer)<0)count_diagnostic(c,TIMER_ERRORS);else count(c,TIMER_CANCELLED);
    }
    if(bpf_map_delete_elem(&timers,&key))count_diagnostic(c,TIMER_ERRORS);
}
#else
static __always_inline void arm(struct counter_values *c,const struct section_admission *admission) {}
static __always_inline void cancel(struct counter_values *c,__u64 sem) {}
#endif
