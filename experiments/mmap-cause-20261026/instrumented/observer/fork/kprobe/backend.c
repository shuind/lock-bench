// SPDX-License-Identifier: GPL-2.0
#include "backend.h"
static const char *programs[]={"fk_begin","fk_end","fk_return"};
const struct backend_ops backend={
    .name="fork/kprobe",.target=OBJECT_FORK,.scheme=SCHEME_KPROBE,
    .supports_timer=0,.lock_symbol=0,
    .programs=programs,.program_count=sizeof(programs)/sizeof(programs[0])
};
