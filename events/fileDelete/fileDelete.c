// events/fileDelete/fileDelete.c
// go:build ignore
#define __TARGET_ARCH_x86
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") __attribute__((weak)) = "GPL";

// Unified event structure for file deletion events.
struct file_delete_event {
    __u32 uid;
    __u32 pid;
    // Event type: 0 for sys_enter_unlink, 1 for sys_enter_unlinkat.
    __u8 event_type;
    // File path being deleted.
    char filepath[512];
    // Only valid for sys_enter_unlinkat; for sys_enter_unlink, set to 0.
    int flag;
} __attribute__((packed));

// Ring buffer map for sending events to userspace.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB
} fileDeleteEventMap SEC(".maps");

// Tracepoint format for sys_enter_unlink.
struct tracepoint_syscalls_sys_enter_unlink {
    __u16 common_type;         // offset: 0, size: 2
    __u8 common_flags;         // offset: 2, size: 1
    __u8 common_preempt_count; // offset: 3, size: 1
    int common_pid;            // offset: 4, size: 4
    int __syscall_nr;          // offset: 8, size: 4
    const char *pathname;      // offset: 16, size: 8
};

// Tracepoint format for sys_enter_unlinkat.
struct tracepoint_syscalls_sys_enter_unlinkat {
    __u16 common_type;         // offset: 0, size: 2
    __u8 common_flags;         // offset: 2, size: 1
    __u8 common_preempt_count; // offset: 3, size: 1
    int common_pid;            // offset: 4, size: 4
    int __syscall_nr;          // offset: 8, size: 4
    int dfd;                   // offset: 16, size: 8
    const char *pathname;      // offset: 24, size: 8
    int flag;                  // offset: 32, size: 8
};

SEC("tracepoint/syscalls/sys_enter_unlink")
int trace_sys_enter_unlink(struct tracepoint_syscalls_sys_enter_unlink *args) {
    struct file_delete_event *e;

    // Reserve space in the ring buffer.
    e = bpf_ringbuf_reserve(&fileDeleteEventMap, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() >> 32;
    e->event_type = 0;

    // Read the pathname from user space.
    bpf_probe_read_user_str(e->filepath, sizeof(e->filepath), args->pathname);
    e->flag = 0; // No flag available in sys_enter_unlink.

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int trace_sys_enter_unlinkat(
    struct tracepoint_syscalls_sys_enter_unlinkat *args) {
    struct file_delete_event *e;

    // Reserve space in the ring buffer.
    e = bpf_ringbuf_reserve(&fileDeleteEventMap, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() >> 32;
    e->event_type = 1; // Indicate sys_enter_unlinkat event.

    // Read the pathname from user space.
    bpf_probe_read_user_str(e->filepath, sizeof(e->filepath), args->pathname);
    e->flag = args->flag;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
