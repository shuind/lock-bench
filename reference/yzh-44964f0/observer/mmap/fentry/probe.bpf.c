// SPDX-License-Identifier: GPL-2.0
#include "../../common/base.bpf.h"
#include "../state.bpf.h"
#define ENTRY(id,fn,write) \
SEC("fentry/" #fn) int BPF_PROG(mf_begin_##id,struct rw_semaphore *sem) {struct counter_values *c=counts_get();if(mm_start(c,ctx,(__u64)sem,write,false))mm_arm(c,(__u64)sem,write);return 0;}
#define RETURN_VOID(id,fn,write) \
SEC("fexit/" #fn) int BPF_PROG(mf_ret_##id,struct rw_semaphore *sem) {struct counter_values *c=counts_get();mm_return(c,(__u64)sem,write,true);return 0;}
#define RETURN_INT(id,fn,write,success) \
SEC("fexit/" #fn) int BPF_PROG(mf_ret_##id,struct rw_semaphore *sem,int ret) {struct counter_values *c=counts_get();if(!(success))mm_cancel(c,(__u64)sem,write);mm_return(c,(__u64)sem,write,success);return 0;}
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
SEC("fentry/up_read") int BPF_PROG(mf_read_up,struct rw_semaphore *sem) {struct counter_values *c=counts_get();mm_cancel(c,(__u64)sem,false);mm_release(c,(__u64)sem,false);return 0;}
SEC("fentry/up_write") int BPF_PROG(mf_write_up,struct rw_semaphore *sem) {struct counter_values *c=counts_get();mm_cancel(c,(__u64)sem,true);mm_release(c,(__u64)sem,true);return 0;}
SEC("fentry/downgrade_write") int BPF_PROG(mf_downgrade,struct rw_semaphore *sem) {struct counter_values *c=counts_get();mm_cancel(c,(__u64)sem,true);if(mm_downgrade(c,ctx,(__u64)sem,true))mm_arm(c,(__u64)sem,false);return 0;}
#include "../exit.bpf.h"

char LICENSE[] SEC("license")="GPL";
