// events/exec/exec_trace.c
// go:build ignore
#define __TARGET_ARCH_x86
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

// Define maximum numbers and lengths for arguments and environment variables.
#define MAX_ARGS 10
#define MAX_ARG_LEN 256
#define MAX_ENVS 10
#define MAX_ENV_LEN 256

char LICENSE[] SEC("license") __attribute__((weak)) = "GPL";

// Tracepoint format for sys_enter_execve.
struct tracepoint_syscalls_sys_enter_execve {
    unsigned short common_type;         // offset: 0, size: 2
    unsigned char common_flags;         // offset: 2, size: 1
    unsigned char common_preempt_count; // offset: 3, size: 1
    int common_pid;                     // offset: 4, size: 4
    int __syscall_nr;                   // offset: 8, size: 4
    const char *filename;               // offset: 16, size: 8
    const char *const *argv;            // offset: 24, size: 8
    const char *const *envp;            // offset: 32, size: 8
};

// Tracepoint format for sys_enter_execveat.
struct tracepoint_syscalls_sys_enter_execveat {
    unsigned short common_type;         // offset: 0, size: 2
    unsigned char common_flags;         // offset: 2, size: 1
    unsigned char common_preempt_count; // offset: 3, size: 1
    int common_pid;                     // offset: 4, size: 4
    int __syscall_nr;                   // offset: 8, size: 4
    int fd;                             // offset: 16, size: 8
    const char *filename;               // offset: 24, size: 8
    const char *const *argv;            // offset: 32, size: 8
    const char *const *envp;            // offset: 40, size: 8
    int flags;                          // offset: 48, size: 8
};

// Event structure that will be submitted to userspace
struct exec_event {
    __u32 uid;
    __u32 pid;
    char command[16];
    char filename[256];
    __u32 argc;
    __u32 envc;
    char args[MAX_ARGS][MAX_ARG_LEN];
    char envs[MAX_ENVS][MAX_ENV_LEN];
} __attribute__((packed));

// Ring buffer map for event delivery.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB
} processCreateEventMap SEC(".maps");

// Tracepoint for sys_enter_execve
// The raw context provides an array of arguments.
// For execve:
//   args[0] = filename
//   args[1] = argv
//   args[2] = envp
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_sys_enter_execve(struct tracepoint_syscalls_sys_enter_execve *ctx) {
    bpf_printk("sys_enter_execve is executed");
    struct exec_event *e;
    const char *filename;
    const char *const *argv;
    const char *const *envp;

    // Reserve the ring buffer
    e = bpf_ringbuf_reserve(&processCreateEventMap, sizeof(struct exec_event),
                            0);
    if (!e)
        return 0;

    e->uid = bpf_get_current_uid_gid() >> 32;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->command, sizeof(e->command));

    // Correctly read the filename using the filename field.
    filename = ctx->filename;
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename);

    // Process argv using ctx->argv.
    argv = ctx->argv;
    e->argc = 0;
#pragma unroll
    for (unsigned int argvIndex = 0; argvIndex < MAX_ARGS; argvIndex++) {
        const char *arg = 0;
        if (bpf_probe_read_user(&arg, sizeof(arg), &argv[argvIndex]) != 0)
            break;
        if (!arg)
            break;
        if (bpf_probe_read_user_str(e->args[argvIndex],
                                    sizeof(e->args[argvIndex]), arg) <= 0)
            break;
        e->argc++;
    }

    // Process envp using ctx->envp.
    envp = ctx->envp;
    e->envc = 0;
#pragma unroll
    for (unsigned int envIndex = 0; envIndex < MAX_ENVS; envIndex++) {
        const char *env = 0;
        if (bpf_probe_read_user(&env, sizeof(env), &envp[envIndex]) != 0)
            break;
        if (!env)
            break;
        if (bpf_probe_read_user_str(e->envs[envIndex],
                                    sizeof(e->envs[envIndex]), env) <= 0)
            break;
        e->envc++;
    }

    bpf_ringbuf_submit(e, 0);

    return 0;
}

//
// Handler for sys_enter_execveat
// In execveat, the kernel passes an extra fd field, and the ordering is:
//   - fd: ctx->fd (ignored here)
//   - filename: ctx->filename
//   - argv: ctx->argv
//   - envp: ctx->envp
//
SEC("tracepoint/syscalls/sys_enter_execveat")
int trace_sys_enter_execveat(
    struct tracepoint_syscalls_sys_enter_execveat *ctx) {
    bpf_printk("sys_enter_execveat is executed");
    struct exec_event *e;
    const char *filename;
    const char *const *argv;
    const char *const *envp;

    // Reserve space in the ring buffer.
    e = bpf_ringbuf_reserve(&processCreateEventMap, sizeof(struct exec_event),
                            0);
    if (!e)
        return 0;

    e->uid = bpf_get_current_uid_gid() >> 32;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->command, sizeof(e->command));

    // Read filename from execveat's tracepoint.
    filename = ctx->filename;
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename);

    // Process argv.
    argv = ctx->argv;
    e->argc = 0;
#pragma unroll
    for (unsigned int argvIndex = 0; argvIndex < MAX_ARGS; argvIndex++) {
        const char *arg = 0;
        if (bpf_probe_read_user(&arg, sizeof(arg), &argv[argvIndex]) != 0)
            break;
        if (!arg)
            break;
        if (bpf_probe_read_user_str(e->args[argvIndex],
                                    sizeof(e->args[argvIndex]), arg) <= 0)
            break;
        e->argc++;
    }

    // Process envp.
    envp = ctx->envp;
    e->envc = 0;
#pragma unroll
    for (unsigned int envIndex = 0; envIndex < MAX_ENVS; envIndex++) {
        const char *env = 0;
        if (bpf_probe_read_user(&env, sizeof(env), &envp[envIndex]) != 0)
            break;
        if (!env)
            break;
        if (bpf_probe_read_user_str(e->envs[envIndex],
                                    sizeof(e->envs[envIndex]), env) <= 0)
            break;
        e->envc++;
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}
