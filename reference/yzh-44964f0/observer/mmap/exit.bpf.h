// Only kretprobe argument stacks need immediate per-task cleanup. Unified lock
// records are reclaimed by user space after checking the thread's birth time.
#ifdef OBSERVER_RETURNS
SEC("tp/sched/sched_process_exit") int mx_exit(void *ctx) {
    struct counter_values *c=NULL;__u64 task=token();
    for(int i=0;i<6;i++) {
        struct mmap_call_key key={.task=task,.kind=i};
        if(bpf_map_lookup_elem(&mm_calls,&key)) {
            if(!c)c=counts_get();bpf_map_delete_elem(&mm_calls,&key);count(c,PAIR_ERRORS);
        }
    }
    return 0;
}
#endif
