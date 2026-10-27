// SPDX-License-Identifier: GPL-2.0
#include "backend.h"
static const char *programs[]={"mt_start","mt_return","mt_release","mt_downgrade"};
const struct backend_ops backend={
    .name="mmap/tracepoint",.target=OBJECT_MMAP,.scheme=SCHEME_TRACEPOINT,
    .supports_timer=0,.lock_symbol=0,
    .programs=programs,.program_count=sizeof(programs)/sizeof(programs[0])
};
