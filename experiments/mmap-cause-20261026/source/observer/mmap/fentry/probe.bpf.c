// SPDX-License-Identifier: GPL-2.0
#include "../../common/base.bpf.h"
#include "../state.bpf.h"
static __always_inline void on_start(struct counter_values *c,void *ctx,__u64 sem,bool write) {
#ifdef OBSERVER_TIMER
    struct mmap_admission a={0};if(mm_start_key(c,ctx,sem,write,false,&a))mm_arm(c,&a);
#else
    mm_start(c,ctx,sem,write,false);
#endif
}
static __always_inline void on_downgrade(struct counter_values *c,void *ctx,__u64 sem) {
#ifdef OBSERVER_TIMER
    struct mmap_admission a={0};if(mm_downgrade_key(c,ctx,sem,true,&a))mm_arm(c,&a);
#else
    mm_downgrade(c,ctx,sem,true);
#endif
}
#define ENTRY(id,fn,write) \
SEC("fentry/" #fn) int BPF_PROG(mf_begin_##id,struct rw_semaphore *sem) {struct counter_values *c=counts_get();on_start(c,ctx,(__u64)sem,write);return 0;}
#define RETURN_VOID(id,fn,write) \
SEC("fexit/" #fn) int BPF_PROG(mf_ret_##id,struct rw_semaphore *sem) {struct counter_values *c=counts_get();mm_return(c,(__u64)sem,write,true);return 0;}
#define RETURN_INT(id,fn,write,success) \
SEC("fexit/" #fn) int BPF_PROG(mf_ret_##id,struct rw_semaphore *sem,int ret) {struct counter_values *c=counts_get();mm_return(c,(__u64)sem,write,success);return 0;}
ENTRY(0,down_read,false)
RETURN_VOID(0,down_read,false)
ENTRY(1,down_read_killable,false)
RETURN_INT(1,down_read_killable,false,ret==0)
ENTRY(2,down_read_trylock,false)
RETURN_INT(2,down_read_trylock,false,ret!=0)
ENTRY(3,down_write,true)
RETURN_VOID(3,down_write,true)
ENTRY(4,down_write_killable,true)
RETURN_INT(4,down_write_killable,true,ret==0)
ENTRY(5,down_write_trylock,true)
RETURN_INT(5,down_write_trylock,true,ret!=0)
SEC("fentry/up_read") int BPF_PROG(mf_read_up,struct rw_semaphore *sem) {struct counter_values *c=counts_get();mm_release(c,(__u64)sem,false);return 0;}
SEC("fentry/up_write") int BPF_PROG(mf_write_up,struct rw_semaphore *sem) {struct counter_values *c=counts_get();mm_release(c,(__u64)sem,true);return 0;}
SEC("fentry/downgrade_write") int BPF_PROG(mf_downgrade,struct rw_semaphore *sem) {struct counter_values *c=counts_get();on_downgrade(c,ctx,(__u64)sem);return 0;}


char LICENSE[] SEC("license")="GPL";
