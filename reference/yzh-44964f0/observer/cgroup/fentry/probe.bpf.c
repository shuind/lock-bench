// SPDX-License-Identifier: GPL-2.0
#include "../../common/base.bpf.h"
#include "../../common/section.bpf.h"
SEC("fentry/percpu_down_write") int BPF_PROG(cf_down,struct percpu_rw_semaphore *sem) {struct counter_values *c=counts_get();
    if(start(c,ctx,(__u64)sem))arm(c,(__u64)sem);return 0;
}
SEC("fexit/percpu_down_write") int BPF_PROG(cf_ret,struct percpu_rw_semaphore *sem) {struct counter_values *c=counts_get();acquired(c,(__u64)sem);return 0;}
SEC("fentry/percpu_up_write") int BPF_PROG(cf_up,struct percpu_rw_semaphore *sem) {struct counter_values *c=counts_get();cancel(c,(__u64)sem);end(c,(__u64)sem);return 0;}

char LICENSE[] SEC("license")="GPL";
