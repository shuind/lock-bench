// Shared state machine for one admitted section, used by cgroup and fork.
HASH(owned,struct trace_key,struct owner,8192);
HASH(states,struct trace_key,struct record,8192);
#ifdef OBSERVER_TIMER
HASH(timers,struct trace_key,struct timer_record,8192);
#endif
#ifdef OBSERVER_RETURNS
HASH(inflight,__u64,struct pending,8192);
#endif
// Retain object identification, but accept every process on the host.
static __always_inline bool admit(__u64 sem) {
    return cfg.enabled && cfg.admit && (!sem || sem==cfg.target_lock);
}
static __always_inline bool start(struct counter_values *c,void *ctx,__u64 sem) {
    count(c,TOTAL_START);if(!admit(sem))return false;
    struct trace_key key=key_for(sem);
    struct owner own={.id=current_id()};if(!own.id)return false;
    if(bpf_map_update_elem(&owned,&key,&own,BPF_NOEXIST)) {count(c,PAIR_ERRORS);return false;}
    count(c,MATCH_START);
    if(cfg.collect!=COLLECT_COUNT) {
        struct record r={.id=own.id,.start_ns=bpf_ktime_get_ns(),.stack_id=-1,.stage=1};
        if(cfg.collect==COLLECT_STACK) {
            r.stack_id=capture_stack(c,ctx);
        }
        if(bpf_map_update_elem(&states,&key,&r,BPF_NOEXIST))count(c,STATE_ERRORS);
    }
    return true;
}
static __always_inline void acquired(struct counter_values *c,__u64 sem) {
    count(c,TOTAL_ACQUIRE);struct trace_key key=key_for(sem);
    if(!bpf_map_lookup_elem(&owned,&key))return;
    count(c,MATCH_ACQUIRE);
    if(cfg.collect!=COLLECT_COUNT) {
        struct record *r=bpf_map_lookup_elem(&states,&key);
        if(!r)count(c,STATE_ERRORS);else {r->acquired_ns=bpf_ktime_get_ns();r->stage=2;}
    }
}
static __always_inline void end(struct counter_values *c,__u64 sem) {
    count(c,TOTAL_END);struct trace_key key=key_for(sem);
    if(!bpf_map_lookup_elem(&owned,&key))return;
    count(c,MATCH_END);
    if(cfg.collect!=COLLECT_COUNT && bpf_map_delete_elem(&states,&key))count(c,STATE_ERRORS);
    if(bpf_map_delete_elem(&owned,&key))count(c,PAIR_ERRORS);
}

#ifdef OBSERVER_TIMER
static int timer_cb(void *map,struct trace_key *key,struct timer_record *timer) {
    struct counter_values *c=counts_get();
    if(!cfg.enabled)return 0;
    count(c,TIMER_FIRED);
    struct record *r=bpf_map_lookup_elem(&states,key);
    struct owner *own=bpf_map_lookup_elem(&owned,key);
    if(!r || !own || r->start_ns!=timer->generation)return 0;
    struct event *e=bpf_ringbuf_reserve(&events,sizeof(*e),0);
    if(!e) {count(c,RING_DROPPED);return 0;}
    *e=(struct event){.state=*r,.now_ns=bpf_ktime_get_ns(),.lock_addr=key->sem};
    bpf_ringbuf_submit(e,0);count(c,RING_SENT);return 0;
}
static __always_inline void arm(struct counter_values *c,__u64 sem) {
    if(!with_timer())return;
    struct trace_key key=key_for(sem);struct record *r=bpf_map_lookup_elem(&states,&key);
    if(!r) {count(c,TIMER_ERRORS);return;}
    struct timer_record zero={.generation=r->start_ns};
    if(bpf_map_update_elem(&timers,&key,&zero,BPF_NOEXIST)) {count(c,TIMER_ERRORS);return;}
    struct timer_record *t=bpf_map_lookup_elem(&timers,&key);
    if(!t || bpf_timer_init(&t->timer,&timers,1) || bpf_timer_set_callback(&t->timer,timer_cb)) {count(c,TIMER_ERRORS);return;}
    t->initialized=1;
    if(bpf_timer_start(&t->timer,cfg.threshold_ns,0))count(c,TIMER_ERRORS);else count(c,TIMER_ARMED);
}
static __always_inline void cancel(struct counter_values *c,__u64 sem) {
    if(!with_timer())return;
    struct trace_key key=key_for(sem);struct timer_record *t=bpf_map_lookup_elem(&timers,&key);
    if(!t)return;
    if(t->initialized) {
        if(bpf_timer_cancel(&t->timer)<0)count(c,TIMER_ERRORS);else count(c,TIMER_CANCELLED);
    }
    if(bpf_map_delete_elem(&timers,&key))count(c,TIMER_ERRORS);
}
#else
static __always_inline void arm(struct counter_values *c,__u64 sem) {}
static __always_inline void cancel(struct counter_values *c,__u64 sem) {}
#endif
