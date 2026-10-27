// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <bpf/libbpf.h>
#include "backend.h"
#include "capabilities.h"
static int configure(struct bpf_object *object,struct config *cfg) {
    struct bpf_map *task=bpf_object__find_map_by_name(object,"mm_task_calls");
    if(!task)return 0;
    struct bpf_map *hash=bpf_object__find_map_by_name(object,"mm_calls");
    if(!hash)return -EPROTO;
    bool supported=libbpf_probe_bpf_map_type((enum bpf_map_type)TASK_STORAGE_MAP,NULL)>0 &&
        libbpf_probe_bpf_helper(BPF_PROG_TYPE_KPROBE,(enum bpf_func_id)CURRENT_TASK_BTF,NULL)>0 &&
        libbpf_probe_bpf_helper(BPF_PROG_TYPE_KPROBE,(enum bpf_func_id)TASK_STORAGE_GET,NULL)>0;
    if(supported)cfg->features|=FEATURE_TASK_CALLS;
    int error=bpf_map__set_autocreate(task,supported);if(error)return error;
    return bpf_map__set_autocreate(hash,!supported);
}
static const char *programs[]={"mk_begin_0","mk_begin_1","mk_begin_2","mk_begin_3","mk_begin_4","mk_begin_5","mk_ret_0","mk_ret_1","mk_ret_2","mk_ret_3","mk_ret_4","mk_ret_5","mk_read_up","mk_write_up","mk_downgrade","mx_exit"};
const struct backend_ops backend={
    .name="mmap/kprobe",.target=OBJECT_MMAP,.scheme=SCHEME_KPROBE,
    .supports_timer=0,.lock_symbol=0,
    .programs=programs,.program_count=sizeof(programs)/sizeof(programs[0]),.configure=configure
};
