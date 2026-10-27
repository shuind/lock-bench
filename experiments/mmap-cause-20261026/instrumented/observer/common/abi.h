// SPDX-License-Identifier: GPL-2.0
#ifndef LOCKBENCH_COMMON_H
#define LOCKBENCH_COMMON_H
enum scheme_mode { SCHEME_FENTRY, SCHEME_KPROBE, SCHEME_CONTENTION, SCHEME_FORK, SCHEME_TRACEPOINT, SCHEME_RAW };
enum object_mode { OBJECT_CGROUP, OBJECT_MMAP, OBJECT_FORK, OBJECT_COUNT };
enum collect_mode { COLLECT_COUNT, COLLECT_STATE, COLLECT_STACK };
enum timeout_mode { TIMEOUT_NONE, TIMEOUT_POLL, TIMEOUT_TIMER };
enum config_feature { FEATURE_TASK_CALLS=1 };
struct config {
    __u64 target_lock, threshold_ns;
    __u32 scheme, collect, enabled, admit, object, rw;
    __u32 timeout,features;
    __u64 pid_ns_dev,pid_ns_ino;
    __u32 event_counts,reserved;
};
struct trace_key { __u64 task, sem; };
struct record { __u64 id, start_ns, acquired_ns; __s32 stack_id; __u32 stage; };
// Birth time keeps records distinct when a task pointer is reused after exit.
struct mmap_key { __u64 sem, task, task_start_ns; __u32 write, reserved; };
struct event { struct record state; __u64 now_ns; __u32 lock_kind, reserved; __u64 lock_addr; };
enum counter {
    TOTAL_START, TOTAL_ACQUIRE, TOTAL_END, MATCH_START, MATCH_ACQUIRE, MATCH_END,
    STATE_ERRORS, STACK_ERRORS, PAIR_ERRORS, TIMER_ARMED, TIMER_CANCELLED,
    TIMER_FIRED, TIMER_ERRORS, RING_SENT, RING_DROPPED, ABORTED,
    TOTAL_READ_START, TOTAL_WRITE_START, TOTAL_READ_RETURN, TOTAL_WRITE_RETURN,
    TOTAL_READ_RELEASE, TOTAL_WRITE_RELEASE, TOTAL_DOWNGRADE,
    MATCH_READ_START, MATCH_WRITE_START, MATCH_READ_ACQUIRE, MATCH_WRITE_ACQUIRE,
    MATCH_READ_RELEASE, MATCH_WRITE_RELEASE, MATCH_READ_FAILED, MATCH_WRITE_FAILED,
    MATCH_DOWNGRADE, MM_DUPLICATE, MM_ABORTED, MM_RETURN_OLD, MM_RELEASE_OLD,
    STACK_COLLISIONS, STACK_CAPACITY_ERRORS, COUNTER_MAX
};
struct counter_values { __u64 value[COUNTER_MAX]; };
// Optional normal activity counts; errors and diagnostic evidence stay enabled.
static inline int counter_is_event(__u32 k) {
    switch(k) {
    case TOTAL_START:case TOTAL_ACQUIRE:case TOTAL_END:
    case MATCH_START:case MATCH_ACQUIRE:case MATCH_END:
    case TIMER_ARMED:case TIMER_CANCELLED:case TIMER_FIRED:case RING_SENT:
    case TOTAL_READ_START:case TOTAL_WRITE_START:
    case TOTAL_READ_RETURN:case TOTAL_WRITE_RETURN:
    case TOTAL_READ_RELEASE:case TOTAL_WRITE_RELEASE:case TOTAL_DOWNGRADE:
    case MATCH_READ_START:case MATCH_WRITE_START:
    case MATCH_READ_ACQUIRE:case MATCH_WRITE_ACQUIRE:
    case MATCH_READ_RELEASE:case MATCH_WRITE_RELEASE:
    case MATCH_READ_FAILED:case MATCH_WRITE_FAILED:case MATCH_DOWNGRADE:return 1;
    default:return 0;
    }
}
#endif
