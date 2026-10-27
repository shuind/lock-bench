// SPDX-License-Identifier: GPL-2.0
#include "backend.h"
static const char *programs[]={"ct_begin","ct_end"};
const struct backend_ops backend={
    .name="cgroup/contention",.target=OBJECT_CGROUP,.scheme=SCHEME_CONTENTION,
    .supports_timer=0,.lock_symbol="cgroup_threadgroup_rwsem",
    .programs=programs,.program_count=sizeof(programs)/sizeof(programs[0])
};
