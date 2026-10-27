// SPDX-License-Identifier: GPL-2.0
#define OBSERVER_MMAP_EVENTS 1
#include "../../common/base.bpf.h"
#include "../state.bpf.h"
// Older kernels pass memcg_path between mm and write; newer ones compute memcg
// information inside the tracepoint. CO-RE removes the incompatible argument path.
struct trace_event_raw_mmap_lock___legacy { __u32 __data_loc_memcg_path; } __attribute__((preserve_access_index));
#define LEGACY_ARGS bpf_core_field_exists(struct trace_event_raw_mmap_lock___legacy,__data_loc_memcg_path)
// Keep each raw context access at an immediate offset; LLVM must not select an
// offset first and then dereference an adjusted raw-tracepoint context pointer.
#define RAW_ARG(ctx,index) ({ __u64 value=(ctx)->args[index];barrier_var(value);value; })
SEC("raw_tp/mmap_lock_start_locking") int mr_start(struct bpf_raw_tracepoint_args *ctx) {struct counter_values *c=counts_get();
    bool write=LEGACY_ARGS ? RAW_ARG(ctx,2) : RAW_ARG(ctx,1);
    mm_start(c,ctx,ctx->args[0]+bpf_core_field_offset(struct mm_struct,mmap_lock),write,true);return 0;
}
SEC("raw_tp/mmap_lock_acquire_returned") int mr_return(struct bpf_raw_tracepoint_args *ctx) {struct counter_values *c=counts_get();
    bool write=LEGACY_ARGS ? RAW_ARG(ctx,2) : RAW_ARG(ctx,1);
    bool success=LEGACY_ARGS ? RAW_ARG(ctx,3) : RAW_ARG(ctx,2);
    mm_return(c,ctx->args[0]+bpf_core_field_offset(struct mm_struct,mmap_lock),write,success);return 0;
}
SEC("raw_tp/mmap_lock_released") int mr_release(struct bpf_raw_tracepoint_args *ctx) {struct counter_values *c=counts_get();
    bool write=LEGACY_ARGS ? RAW_ARG(ctx,2) : RAW_ARG(ctx,1);
    mm_release(c,ctx->args[0]+bpf_core_field_offset(struct mm_struct,mmap_lock),write);return 0;
}
SEC("kprobe/downgrade_write") int mt_downgrade(struct pt_regs *ctx) {struct counter_values *c=counts_get();mm_downgrade(c,ctx,PT_REGS_PARM1(ctx),false);return 0;}



char LICENSE[] SEC("license")="GPL";
