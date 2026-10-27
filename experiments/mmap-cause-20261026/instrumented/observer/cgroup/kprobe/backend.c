// SPDX-License-Identifier: GPL-2.0
#include "backend.h"
static const char *programs[]={"cg_down","cg_ret","cg_up"};
const struct backend_ops backend={
    .name="cgroup/kprobe",.target=OBJECT_CGROUP,.scheme=SCHEME_KPROBE,
    .supports_timer=0,.lock_symbol="cgroup_threadgroup_rwsem",
    .programs=programs,.program_count=sizeof(programs)/sizeof(programs[0])
};
