// SPDX-License-Identifier: GPL-2.0
#ifndef LOCKBENCH_BACKEND_H
#define LOCKBENCH_BACKEND_H
#include <linux/types.h>
#include "abi.h"
struct bpf_object;
struct backend_ops {
    const char *name;
    unsigned target,scheme,supports_timer;
    const char *lock_symbol;
    const char *const *programs;
    unsigned program_count;
    // Optional capability selection before map creation; returns negative errno.
    int (*configure)(struct bpf_object *,struct config *);
};
extern const struct backend_ops backend;
#endif
