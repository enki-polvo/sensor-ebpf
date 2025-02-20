//go:ignore build

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// /sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/format
struct tracepoint_syscalls_sys_enter_openat {
    __u64 __unused;
    __u32 syscall_nr;
    int dfd;
    const char *filename;
    int flags;
    umode_t mode;
};

// The data structure that will be sent to user space for single file creation
// event
struct file_create_event {
    __u32 uid;
    __u32 pid;
    char filename[1024];
    int flags;
    umode_t mode;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB
} fileCreateEventMap SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_sys_enter_openat(struct tracepoint_syscalls_sys_enter_openat *args) {
    struct file_create_event *e;

    // Allocate space in the ring buffer
    e = bpf_ringbuf_reserve(&fileCreateEventMap,
                            sizeof(struct file_create_event), 0);
    if (!e)
        return 0;

    // Gather data
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() >> 32;
    bpf_probe_read_str(e->filename, sizeof(e->filename), args->filename);
    e->flags = args->flags;
    e->mode = args->mode;

    // Submit the event to user space
    bpf_ringbuf_submit(e, 0);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
