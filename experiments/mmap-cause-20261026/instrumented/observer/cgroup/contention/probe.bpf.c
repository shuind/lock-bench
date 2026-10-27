// SPDX-License-Identifier: GPL-2.0
#include "../../common/base.bpf.h"
#include "../../common/section.bpf.h"
SEC("tp/lock/contention_begin") int ct_begin(struct trace_event_raw_contention_begin *ctx) {struct counter_values *c=counts_get();start(c,ctx,(__u64)ctx->lock_addr);return 0;}
SEC("tp/lock/contention_end") int ct_end(struct trace_event_raw_contention_end *ctx) {struct counter_values *c=counts_get();end(c,(__u64)ctx->lock_addr);return 0;}

char LICENSE[] SEC("license")="GPL";
