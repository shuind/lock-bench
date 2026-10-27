// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "abi.h"
volatile struct config cfg;
// Immutable choices are frozen at load time so the verifier can remove unused
// count/state/stack and namespace branches. Only enabled/admit remain mutable.
const volatile struct config settings;
struct timer_record { struct bpf_timer timer; __u64 generation; __u32 initialized, reserved; };
struct pending { __u64 sem[4]; __u32 accepted[4], count, reserved; };
#define HASH(name, key_t, value_t, capacity) struct { \
    __uint(type,BPF_MAP_TYPE_HASH); __uint(max_entries,capacity); \
    __type(key,key_t); __type(value,value_t); } name SEC(".maps")
#ifdef OBSERVER_TASK_PAIRING
struct task_counter_values { struct counter_values counters; __u64 pending_calls; };
#define COUNTER_STORAGE struct task_counter_values
#else
#define COUNTER_STORAGE struct counter_values
#endif
struct { __uint(type,BPF_MAP_TYPE_PERCPU_ARRAY); __uint(max_entries,1);
    __type(key,__u32); __type(value,COUNTER_STORAGE); } counters SEC(".maps");
#ifndef STACK_PRIMARY_CAPACITY
#define STACK_PRIMARY_CAPACITY 4096
#endif
struct { __uint(type,BPF_MAP_TYPE_STACK_TRACE); __uint(max_entries,STACK_PRIMARY_CAPACITY);
    __uint(key_size,4); __uint(value_size,32*8); } stacks SEC(".maps");
#ifndef STACK_OVERFLOW_CAPACITY
#define STACK_OVERFLOW_CAPACITY 4096
#endif
struct { __uint(type,BPF_MAP_TYPE_STACK_TRACE); __uint(max_entries,STACK_OVERFLOW_CAPACITY);
    __uint(key_size,4); __uint(value_size,32*8); } stack_overflow SEC(".maps");
#ifdef OBSERVER_TIMER
struct { __uint(type,BPF_MAP_TYPE_RINGBUF); __uint(max_entries,1<<22); } events SEC(".maps");
#endif
static __always_inline struct counter_values *counts_lookup(void) {
    __u32 zero=0;return bpf_map_lookup_elem(&counters,&zero);
}
static __always_inline struct counter_values *counts_get(void) {
    // Frozen at load time: event_counts=0 removes the eager lookup and updates.
    if(!settings.event_counts || !cfg.enabled)return NULL;
    return counts_lookup();
}
static __always_inline void count(struct counter_values *c,__u32 k) {
    if(c)c->value[k]++;
}
static __always_inline void count_diagnostic(struct counter_values *c,__u32 k) {
    // Diagnostics stay visible without eager normal event counting.
    if(!c) {if(!cfg.enabled)return;c=counts_lookup();}
    count(c,k);
}
// Keep both colliding stacks intact. Never reuse or overwrite a stack ID.
static __always_inline int capture_stack(struct counter_values *c,void *ctx) {
    int id=bpf_get_stackid(ctx,&stacks,0);
    if(id==-17 || id==-12) { // Collision or exhausted primary storage: try overflow.
        if(id==-17)count_diagnostic(c,STACK_COLLISIONS);
        id=bpf_get_stackid(ctx,&stack_overflow,0);
        if(id>=0)return 4096+id;
    }
    if(id<0) {
        count_diagnostic(c,STACK_ERRORS);
        if(id==-12)count_diagnostic(c,STACK_CAPACITY_ERRORS);
    }
    return id;
}
// Only the address is used as an opaque key here; no field is dereferenced.
// Keep this identity helper available on older kernels as well.
static __always_inline __u64 token(void) {return bpf_get_current_task();}
// Match record IDs to the PID namespace of the observer's /proc mount.
static __always_inline __u64 current_id(void) {
    if(!settings.pid_ns_ino)return bpf_get_current_pid_tgid();
    struct bpf_pidns_info info={0};
    if(bpf_get_ns_current_pid_tgid(settings.pid_ns_dev,settings.pid_ns_ino,&info,sizeof(info)))return 0;
    return ((__u64)info.tgid<<32)|info.pid;
}
static __always_inline struct trace_key key_for(__u64 sem) {return (struct trace_key){token(),sem};}
static __always_inline bool with_timer(void) {return settings.timeout==TIMEOUT_TIMER;}
