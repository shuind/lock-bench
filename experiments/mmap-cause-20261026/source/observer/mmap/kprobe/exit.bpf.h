// SPDX-License-Identifier: GPL-2.0
static __always_inline int mm_exit_task(void *ctx) {
    struct mmap_call_storage *saved=bpf_task_storage_get(&mm_task_calls,mm_task(),NULL,0);
    if(!saved)return 0;
    struct counter_values *c=NULL;
    for(int i=0;i<6;i++)if(saved->calls[i].count) {
        if(!c) {__u32 zero=0;c=bpf_map_lookup_elem(&counters,&zero);}
        if(!c)return 0;
        saved->calls[i].count=0;mm_pending_count(c,false);
        if(cfg.enabled)count_diagnostic(c,PAIR_ERRORS);
    }
    return 0;
}

// Only kretprobe argument stacks need immediate per-task cleanup. Unified lock
// records are reclaimed by user space after checking the thread's birth time.
static __always_inline int mm_exit_hash(void *ctx) {
    struct counter_values *c=NULL;__u64 task=token();
    for(int i=0;i<6;i++) {
        struct mmap_call_key key={.task=task,.kind=i};
        if(bpf_map_lookup_elem(&mm_calls,&key)) {
            if(!c)c=counts_get();bpf_map_delete_elem(&mm_calls,&key);count_diagnostic(c,PAIR_ERRORS);
        }
    }
    return 0;
}

SEC("tp/sched/sched_process_exit") int mx_exit(void *ctx) {
    if(settings.features&FEATURE_TASK_CALLS)return mm_exit_task(ctx);
    return mm_exit_hash(ctx);
}
