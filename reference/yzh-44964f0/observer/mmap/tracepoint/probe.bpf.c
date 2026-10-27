// SPDX-License-Identifier: GPL-2.0
#include "../../common/base.bpf.h"
#include "../state.bpf.h"
SEC("tp/mmap_lock/mmap_lock_start_locking") int mt_start(struct trace_event_raw_mmap_lock *ctx) {struct counter_values *c=counts_get();
    mm_start(c,ctx,(__u64)ctx->mm+bpf_core_field_offset(struct mm_struct,mmap_lock),ctx->write,true);return 0;
}
SEC("tp/mmap_lock/mmap_lock_acquire_returned") int mt_return(struct trace_event_raw_mmap_lock_acquire_returned *ctx) {struct counter_values *c=counts_get();
    mm_return(c,(__u64)ctx->mm+bpf_core_field_offset(struct mm_struct,mmap_lock),ctx->write,ctx->success);return 0;
}
SEC("tp/mmap_lock/mmap_lock_released") int mt_release(struct trace_event_raw_mmap_lock *ctx) {struct counter_values *c=counts_get();
    mm_release(c,(__u64)ctx->mm+bpf_core_field_offset(struct mm_struct,mmap_lock),ctx->write);return 0;
}
SEC("kprobe/downgrade_write") int mt_downgrade(struct pt_regs *ctx) {struct counter_values *c=counts_get();mm_downgrade(c,ctx,PT_REGS_PARM1(ctx),false);return 0;}

#include "../exit.bpf.h"

char LICENSE[] SEC("license")="GPL";
