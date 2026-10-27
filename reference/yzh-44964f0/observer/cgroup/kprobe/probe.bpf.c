// SPDX-License-Identifier: GPL-2.0
#define OBSERVER_RETURNS 1
#include "../../common/base.bpf.h"
#include "../../common/section.bpf.h"
SEC("kprobe/percpu_down_write") int cg_down(struct pt_regs *ctx) {struct counter_values *c=counts_get();
    __u64 sem=PT_REGS_PARM1(ctx),k=token();
    bool accepted=start(c,ctx,sem);
    struct pending *p=bpf_map_lookup_elem(&inflight,&k);
    if(!accepted && !p)return 0;
    if(!p) {
        struct pending zero={0};
        if(bpf_map_update_elem(&inflight,&k,&zero,BPF_NOEXIST)) {count(c,PAIR_ERRORS);return 0;}
        p=bpf_map_lookup_elem(&inflight,&k);
    }
    if(!p || p->count>=4) {count(c,PAIR_ERRORS);return 0;}
    __u32 i=p->count;p->sem[i]=sem;p->accepted[i]=accepted;p->count=i+1;return 0;
}
SEC("kretprobe/percpu_down_write") int cg_ret(struct pt_regs *ctx) {struct counter_values *c=counts_get();
    __u64 k=token();struct pending *p=bpf_map_lookup_elem(&inflight,&k);
    if(!p || !p->count) {count(c,TOTAL_ACQUIRE);return 0;}
    __u32 i=p->count-1;if(i>=4) {count(c,PAIR_ERRORS);return 0;}
    if(p->accepted[i])acquired(c,p->sem[i]);else count(c,TOTAL_ACQUIRE);
    p->count=i;if(!i && bpf_map_delete_elem(&inflight,&k))count(c,PAIR_ERRORS);return 0;
}
SEC("kprobe/percpu_up_write") int cg_up(struct pt_regs *ctx) {struct counter_values *c=counts_get();end(c,PT_REGS_PARM1(ctx));return 0;}

char LICENSE[] SEC("license")="GPL";
