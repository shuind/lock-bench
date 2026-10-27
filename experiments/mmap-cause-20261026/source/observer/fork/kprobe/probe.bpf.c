// SPDX-License-Identifier: GPL-2.0
#include "../../common/base.bpf.h"
#include "../../common/section.bpf.h"
SEC("kprobe/cgroup_can_fork") int fk_begin(struct pt_regs *ctx) {struct counter_values *c=counts_get();start(c,ctx,0);return 0;}
SEC("kprobe/cgroup_post_fork") int fk_end(struct pt_regs *ctx) {struct counter_values *c=counts_get();end(c,0);return 0;}

// Failed fork never reaches cgroup_post_fork; retire its admitted state.
SEC("kretprobe/cgroup_can_fork") int fk_return(struct pt_regs *ctx) {struct counter_values *c=counts_get();
    if(PT_REGS_RC(ctx)) {
        struct trace_key key=key_for(0);
        if(bpf_map_lookup_elem(&states,&key)) {end(c,0);count_diagnostic(c,ABORTED);}
    }
    return 0;
}

char LICENSE[] SEC("license")="GPL";
