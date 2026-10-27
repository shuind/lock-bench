// SPDX-License-Identifier: GPL-2.0
#include "backend.h"
static const char *programs[]={"cf_down","cf_ret","cf_up"};
const struct backend_ops backend={
    .name="cgroup/fentry",.target=OBJECT_CGROUP,.scheme=SCHEME_FENTRY,
    .supports_timer=1,.lock_symbol="cgroup_threadgroup_rwsem",
    .programs=programs,.program_count=sizeof(programs)/sizeof(programs[0])
};
