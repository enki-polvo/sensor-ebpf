// events/processTerminate/processTerminate_full_encapsulated.c
// go:build ignore
#define __TARGET_ARCH_x86
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") __attribute__((weak)) = "GPL";

// Tracepoint format for both sys_exit_execve and sys_exit_execveat.
struct tracepoint_syscalls_sys_exit_execve_or_execveat {
    unsigned short common_type;         // offset: 0, size: 2
    unsigned char common_flags;         // offset: 2, size: 1
    unsigned char common_preempt_count; // offset: 3, size: 1
    int common_pid;                     // offset: 4, size: 4
    int __syscall_nr;                   // offset: 8, size: 4
    long ret;                           // offset: 16, size: 8
};

// Extended event structure including the full command line.
#define MAX_CMDLINE_LENGTH_IN_BYTE 512
struct exec_terminate_event_full {
    __u32 uid;
    __u32 pid;
    long ret;
    char cmdline[MAX_CMDLINE_LENGTH_IN_BYTE];
} __attribute__((packed));

// Ring buffer map for event delivery.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB
} processTerminateEventMap SEC(".maps");

// Replace null terminators in a buffer with spaces.
// So, each argument will be clearly distinguishable with spaces clearly.
static __always_inline void replace_nulls_with_spaces(char *buf, int buf_size) {
    // Unroll a loop with a fixed bound.
#pragma unroll
    for (int i = 0; i < MAX_CMDLINE_LENGTH_IN_BYTE; i++) {
        // Ensure we don't go past the actual buffer size.
        if (i >= buf_size)
            break;
        // Replace null terminators with a space, but leave the final null.
        if (buf[i] == '\0' && i != buf_size - 1)
            buf[i] = ' ';
    }
}

// Do right trim of the string.
// It will be used to remove the unnecessary trailing spaces,
// to make the output more readable.
static __always_inline void right_trim(char *buf, int buf_size) {
    // Don't unroll this loop due to the BPF stack limit and expected short loop
    // count. Iterate from the end of the buffer to the beginning.
    for (int j = MAX_CMDLINE_LENGTH_IN_BYTE - 1; j >= 0; j--) {
        int i = buf_size - 1 - j;
        // If we run out of buffer, break.
        if (i < 0)
            break;
        // If the character is a space, replace it with a null terminator.
        if (buf[i] == ' ')
            buf[i] = '\0';
        else
            break;
    }
}

// Helper function to read the full command line (argv) from the current task.
// Returns 0 on success, -1 on failure.
static __always_inline int read_cmdline(char *buf, int buf_size) {
    struct task_struct *task;
    struct mm_struct *mm = 0;
    unsigned long arg_start = 0, arg_end = 0, size = 0;

    task = (struct task_struct *)bpf_get_current_task();
    if (bpf_probe_read(&mm, sizeof(mm), // NOLINT
                       &task->mm) != 0 ||
        !mm)
        return -1;

    if (bpf_probe_read(&arg_start, sizeof(arg_start), &mm->arg_start) != 0 ||
        bpf_probe_read(&arg_end, sizeof(arg_end), &mm->arg_end) != 0)
        return -1;

    size = arg_end - arg_start;
    if (size >= buf_size)
        size = buf_size - 1;

    if (bpf_probe_read_user(buf, size, (void *)arg_start) < 0)
        return -1;

    // Post-process the buffer to replace nulls with spaces and right trim.
    buf[size] = '\0';
    replace_nulls_with_spaces(buf, buf_size);
    right_trim(buf, buf_size);

    return 0;
}

//
// Tracepoint handler for sys_exit_execve with full command line extraction.
//
SEC("tracepoint/syscalls/sys_exit_execve")
int trace_sys_exit_execve(
    struct tracepoint_syscalls_sys_exit_execve_or_execveat *ctx) {
    struct exec_terminate_event_full *e;
    int ret;

    e = bpf_ringbuf_reserve(&processTerminateEventMap, sizeof(*e), 0);
    if (!e)
        return 0;

    e->uid = bpf_get_current_uid_gid() >> 32;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->ret = ctx->ret;
    e->cmdline[0] = '\0';

    // Try to fill the command line using our helper function.
    ret = read_cmdline(e->cmdline, sizeof(e->cmdline));
    // On failure, e->cmdline remains an empty string.

    bpf_ringbuf_submit(e, 0);
    return 0;
}

//
// Tracepoint handler for sys_exit_execveat with full command line extraction.
//
SEC("tracepoint/syscalls/sys_exit_execveat")
int trace_sys_exit_execveat(
    struct tracepoint_syscalls_sys_exit_execve_or_execveat *ctx) {
    struct exec_terminate_event_full *e;
    int ret;

    e = bpf_ringbuf_reserve(&processTerminateEventMap, sizeof(*e), 0);
    if (!e)
        return 0;

    e->uid = bpf_get_current_uid_gid() >> 32;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->ret = ctx->ret;
    e->cmdline[0] = '\0';

    ret = read_cmdline(e->cmdline, sizeof(e->cmdline));
    // On failure, we just leave the cmdline empty.

    bpf_ringbuf_submit(e, 0);
    return 0;
}
