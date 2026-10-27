// SPDX-License-Identifier: GPL-2.0
#include "../../common/base.bpf.h"
#include "../../common/section.bpf.h"
SEC("fentry/percpu_down_write") int BPF_PROG(cf_down,struct percpu_rw_semaphore *sem) {struct counter_values *c=counts_get();
#ifdef OBSERVER_TIMER
    struct section_admission a={0};if(start_key(c,ctx,(__u64)sem,&a))arm(c,&a);
#else
    start(c,ctx,(__u64)sem);
#endif
    return 0;
}
SEC("fexit/percpu_down_write") int BPF_PROG(cf_ret,struct percpu_rw_semaphore *sem) {struct counter_values *c=counts_get();acquired(c,(__u64)sem);return 0;}
SEC("fentry/percpu_up_write") int BPF_PROG(cf_up,struct percpu_rw_semaphore *sem) {struct counter_values *c=counts_get();cancel(c,(__u64)sem);end(c,(__u64)sem);return 0;}

char LICENSE[] SEC("license")="GPL";
