// SPDX-License-Identifier: GPL-2.0
#include "backend.h"
static const char *programs[]={"mf_begin_0","mf_begin_1","mf_begin_2","mf_begin_3","mf_begin_4","mf_begin_5","mf_ret_0","mf_ret_1","mf_ret_2","mf_ret_3","mf_ret_4","mf_ret_5","mf_read_up","mf_write_up","mf_downgrade"};
const struct backend_ops backend={
    .name="mmap/fentry",.target=OBJECT_MMAP,.scheme=SCHEME_FENTRY,
    .supports_timer=1,.lock_symbol=0,
    .programs=programs,.program_count=sizeof(programs)/sizeof(programs[0])
};
