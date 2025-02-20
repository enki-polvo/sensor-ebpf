// go:build ignore
#define __TARGET_ARCH_x86
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// Tracepoint format for sys_enter_openat.
struct tracepoint_syscalls_sys_enter_openat {
    __u16 common_type;         // offset: 0, size: 2
    __u8 common_flags;         // offset: 2, size: 1
    __u8 common_preempt_count; // offset: 3, size: 1
    int common_pid;            // offset: 4, size: 4
    int __syscall_nr;          // offset: 8, size: 4
    long dfd;                  // offset: 16, size: 8
    const char *filename;      // offset: 24, size: 8
    long flags;                // offset: 32, size: 8
    unsigned long mode;        // offset: 40, size: 8
};

// Tracepoint format for sys_enter_open.
struct tracepoint_syscalls_sys_enter_open {
    __u16 common_type;         // offset: 0, size: 2
    __u8 common_flags;         // offset: 2, size: 1
    __u8 common_preempt_count; // offset: 3, size: 1
    int common_pid;            // offset: 4, size: 4
    int __syscall_nr;          // offset: 8, size: 4
    const char *filename;      // offset: 16, size: 8
    long flags;                // offset: 24, size: 8
    unsigned long mode;        // offset: 32, size: 8
};

// Event structure to be sent to userspace.
// Marked as packed to ensure identical memory layout between C and Go.
struct file_create_event {
    __u32 uid;
    __u32 pid;
    char filename[256];
    long flags;
    unsigned long mode;
    __u32 event_type; // 1: open, 2: openat
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB
} fileCreateEventMap SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_sys_enter_openat(struct tracepoint_syscalls_sys_enter_openat *args) {
    struct file_create_event *e;

    // Reserve space in the ring buffer.
    e = bpf_ringbuf_reserve(&fileCreateEventMap,
                            sizeof(struct file_create_event), 0);
    if (!e)
        return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() >> 32;
    // Copy the filename from user space.
    bpf_probe_read_user_str(e->filename, sizeof(e->filename), args->filename);
    e->flags = args->flags;
    e->mode = args->mode;
    e->event_type = 2; // Mark as openat

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_open")
int trace_sys_enter_open(struct tracepoint_syscalls_sys_enter_open *args) {
    struct file_create_event *e;

    // Reserve space in the ring buffer.
    e = bpf_ringbuf_reserve(&fileCreateEventMap,
                            sizeof(struct file_create_event), 0);
    if (!e)
        return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() >> 32;
    // Copy the filename from user space.
    bpf_probe_read_user_str(e->filename, sizeof(e->filename), args->filename);
    e->flags = args->flags;
    e->mode = args->mode;
    e->event_type = 1; // Mark as open

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
