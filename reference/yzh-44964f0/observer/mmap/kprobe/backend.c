// SPDX-License-Identifier: GPL-2.0
#include "backend.h"
static const char *programs[]={"mk_begin_0","mk_begin_1","mk_begin_2","mk_begin_3","mk_begin_4","mk_begin_5","mk_ret_0","mk_ret_1","mk_ret_2","mk_ret_3","mk_ret_4","mk_ret_5","mk_read_up","mk_write_up","mk_downgrade","mx_exit"};
const struct backend_ops backend={
    .name="mmap/kprobe",.target=OBJECT_MMAP,.scheme=SCHEME_KPROBE,
    .supports_timer=0,.lock_symbol=0,
    .programs=programs,.program_count=sizeof(programs)/sizeof(programs[0])
};
