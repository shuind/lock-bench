// SPDX-License-Identifier: GPL-2.0
#include "backend.h"
static const char *programs[]={"mr_start","mr_return","mr_release","mt_downgrade"};
const struct backend_ops backend={
    .name="mmap/raw",.target=OBJECT_MMAP,.scheme=SCHEME_RAW,
    .supports_timer=0,.lock_symbol=0,
    .programs=programs,.program_count=sizeof(programs)/sizeof(programs[0])
};
