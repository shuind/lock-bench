// SPDX-License-Identifier: GPL-2.0
#define OBSERVER_RETURNS 1
#include "../../common/base.bpf.h"
#include "../state.bpf.h"
#define PAIR(id,fn,write,success) \
SEC("kprobe/" #fn) int mk_begin_##id(struct pt_regs *ctx) {struct counter_values *c=counts_get();mm_kstart(c,ctx,PT_REGS_PARM1(ctx),write,id);return 0;} \
SEC("kretprobe/" #fn) int mk_ret_##id(struct pt_regs *ctx) {struct counter_values *c=counts_get();mm_kreturn(c,write,id,success);return 0;}
PAIR(0,down_read,false,true)
PAIR(1,down_read_killable,false,PT_REGS_RC(ctx)==0)
PAIR(2,down_read_trylock,false,PT_REGS_RC(ctx)!=0)
PAIR(3,down_write,true,true)
PAIR(4,down_write_killable,true,PT_REGS_RC(ctx)==0)
PAIR(5,down_write_trylock,true,PT_REGS_RC(ctx)!=0)
SEC("kprobe/up_read") int mk_read_up(struct pt_regs *ctx) {struct counter_values *c=counts_get();mm_release(c,PT_REGS_PARM1(ctx),false);return 0;}
SEC("kprobe/up_write") int mk_write_up(struct pt_regs *ctx) {struct counter_values *c=counts_get();mm_release(c,PT_REGS_PARM1(ctx),true);return 0;}
SEC("kprobe/downgrade_write") int mk_downgrade(struct pt_regs *ctx) {struct counter_values *c=counts_get();mm_downgrade(c,ctx,PT_REGS_PARM1(ctx),true);return 0;}
#include "../exit.bpf.h"

char LICENSE[] SEC("license")="GPL";
