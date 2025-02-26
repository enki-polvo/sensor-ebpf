// events/processTerminate/processTerminate.c
// go:build ignore
#define __TARGET_ARCH_x86
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") __attribute__((weak)) = "GPL";

// Tracepiont format for both sys_exit_execve and sys_exit_execveat.
struct tracepoint_syscalls_sys_exit_execve_or_execveat {
    unsigned short common_type;         // offset: 0, size: 2
    unsigned char common_flags;         // offset: 2, size: 1
    unsigned char common_preempt_count; // offset: 3, size: 1
    int common_pid;                     // offset: 4, size: 4
    int __syscall_nr;                   // offset: 8, size: 4
    long ret;                           // offset: 16, size: 8
};

// Event structure that will be submitted to userspace
struct exec_terminate_event {
    __u32 uid;
    __u32 pid;
    long ret;
} __attribute__((packed));

// Ring buffer map for event delivery.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB
} processTerminateEventMap SEC(".maps");

// This function is used to handle both sys_exit_execve and sys_exit_execveat
int trace_common_exec_terminate_events(
    struct tracepoint_syscalls_sys_exit_execve_or_execveat *ctx) {
    struct exec_terminate_event *e;

    // Reserve the ring buffer
    e = bpf_ringbuf_reserve(&processTerminateEventMap,
                            sizeof(struct exec_terminate_event), 0);
    if (!e)
        return 0;

    e->uid = bpf_get_current_uid_gid() >> 32;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->ret = ctx->ret;

    bpf_ringbuf_submit(e, 0);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_execve")
int trace_sys_exit_execve(
    struct tracepoint_syscalls_sys_exit_execve_or_execveat *ctx) {
    return trace_common_exec_terminate_events(ctx);
}

SEC("tracepoint/syscalls/sys_exit_execveat")
int trace_sys_exit_execveat(
    struct tracepoint_syscalls_sys_exit_execve_or_execveat *ctx) {
    return trace_common_exec_terminate_events(ctx);
}
