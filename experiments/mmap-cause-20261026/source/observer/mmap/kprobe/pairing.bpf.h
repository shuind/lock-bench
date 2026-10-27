// SPDX-License-Identifier: GPL-2.0
// Return arguments are private to the mmap kprobe backend.
#include "capabilities.h"
struct mmap_call_key { __u64 task; __u32 kind,pad; };
struct mmap_pending { struct pending calls; __u64 task_start_ns; };
struct mmap_call_storage { __u64 task_start_ns; struct pending calls[6]; };
struct { __uint(type,TASK_STORAGE_MAP); __uint(map_flags,BPF_F_NO_PREALLOC);
    __type(key,int); __type(value,struct mmap_call_storage); } mm_task_calls SEC(".maps");
static __always_inline void mm_pending_count(struct counter_values *c,bool opening) {
    // This gauge is required for drain/export, even with event counts disabled.
    if(!c)c=counts_lookup();
    if(!c)return;
    struct task_counter_values *values=(void *)c;
    if(opening)values->pending_calls++;else values->pending_calls--;
}
HASH(mm_calls,struct mmap_call_key,struct mmap_pending,8192);
// Retain idle argument slots until task exit. Active records are not evictable.
static __always_inline void mm_kstart_task(struct counter_values *c,void *ctx,__u64 sem,bool write,__u32 kind) {
    if(!cfg.enabled)return;
    // Map helpers can scalarize key copies on older verifiers. Keep this pointer.
    struct task_struct *task=mm_task();
    struct mmap_admission admitted={0};
    bool accepted=mm_start_task(c,ctx,sem,write,false,task,&admitted);
    struct mmap_call_storage *saved=bpf_task_storage_get(&mm_task_calls,task,NULL,
        accepted ? TASK_STORAGE_CREATE : 0);
    if(!saved) {if(accepted)count_diagnostic(c,PAIR_ERRORS);return;}
    struct pending *p=&saved->calls[kind];
    // Keep the checked index across the optional gauge lookup helper.
    __u32 i=p->count;
    if(!accepted && !i)return;
    if(i>=4) {count_diagnostic(c,PAIR_ERRORS);return;}
    if(!i) {
        if(!saved->task_start_ns)saved->task_start_ns=admitted.key.task_start_ns;
        mm_pending_count(c,true);
    }
    p->sem[i]=sem;p->accepted[i]=accepted;p->count=i+1;
}
static __always_inline void mm_kreturn_task(struct counter_values *c,bool write,__u32 kind,bool success) {
    if(!cfg.enabled)return;
    count(c,write ? TOTAL_WRITE_RETURN : TOTAL_READ_RETURN);
    struct task_struct *task=mm_task();
    struct mmap_call_storage *saved=bpf_task_storage_get(&mm_task_calls,task,NULL,0);
    if(!saved)return;
    struct pending *p=&saved->calls[kind];
    if(!p->count)return;
    __u32 i=p->count-1;if(i>=4) {count_diagnostic(c,PAIR_ERRORS);return;}
    if(p->accepted[i]) {
        struct mmap_key record=mmap_key_make(p->sem[i],(__u64)task,saved->task_start_ns,write);
        mm_return_key(c,&record,success,task);
    }
    p->count=i;if(!i)mm_pending_count(c,false);
}


static __always_inline void mm_kstart_hash(struct counter_values *c,void *ctx,__u64 sem,bool write,__u32 kind) {
    if(!cfg.enabled)return;
    struct mmap_admission admitted={0};
    bool accepted=mm_start_key(c,ctx,sem,write,false,&admitted);
    struct mmap_call_key key={.task=admitted.key.task ? admitted.key.task : token(),.kind=kind};
    struct mmap_pending *saved=bpf_map_lookup_elem(&mm_calls,&key);
    if(!accepted && !saved)return;
    if(!saved) {
        struct mmap_pending first={.calls={.sem={sem},.accepted={accepted},.count=1},
            .task_start_ns=admitted.key.task_start_ns};
        if(bpf_map_update_elem(&mm_calls,&key,&first,BPF_NOEXIST))count_diagnostic(c,PAIR_ERRORS);
        return;
    }
    struct pending *p=&saved->calls;
    if(p->count>=4) {count_diagnostic(c,PAIR_ERRORS);return;}
    __u32 i=p->count;p->sem[i]=sem;p->accepted[i]=accepted;p->count=i+1;
}
static __always_inline void mm_kreturn_hash(struct counter_values *c,bool write,__u32 kind,bool success) {
    if(!cfg.enabled)return;
    count(c,write ? TOTAL_WRITE_RETURN : TOTAL_READ_RETURN);
    struct task_struct *task=mm_task();
    struct mmap_call_key key={.task=(__u64)task,.kind=kind};struct mmap_pending *saved=bpf_map_lookup_elem(&mm_calls,&key);
    if(!saved || !saved->calls.count)return;
    struct pending *p=&saved->calls;
    __u32 i=p->count-1;if(i>=4) {count_diagnostic(c,PAIR_ERRORS);return;}
    if(p->accepted[i]) {
        struct mmap_key record=mmap_key_make(p->sem[i],key.task,saved->task_start_ns,write);
        mm_return_key(c,&record,success,task);
    }
    p->count=i;if(!i && bpf_map_delete_elem(&mm_calls,&key))count_diagnostic(c,PAIR_ERRORS);
}

static __always_inline void mm_kstart(struct counter_values *c,void *ctx,__u64 sem,bool write,__u32 kind) {
    if(settings.features&FEATURE_TASK_CALLS)mm_kstart_task(c,ctx,sem,write,kind);
    else mm_kstart_hash(c,ctx,sem,write,kind);
}
static __always_inline void mm_kreturn(struct counter_values *c,bool write,__u32 kind,bool success) {
    if(settings.features&FEATURE_TASK_CALLS)mm_kreturn_task(c,write,kind,success);
    else mm_kreturn_hash(c,write,kind,success);
}
