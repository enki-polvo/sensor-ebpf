// events/bashReadline/bashReadline.c
// go:build ignore
#define __TARGET_ARCH_x86
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") __attribute__((weak)) = "GPL";

struct bash_readline_event {
    __u32 uid;
    __u32 pid;
    char commandline[256];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __type(value, struct bash_readline_event);
} bashReadlineEventMap SEC(".maps");

// Since we're tracking the RC register, we're using a uretprobe
SEC("uretprobe/bash_readline")
int uprobe_bash_readline(struct pt_regs *ctx) {
    struct bash_readline_event e;

    e.pid = bpf_get_current_pid_tgid() >> 32;
    e.uid = bpf_get_current_uid_gid() >> 32;

    // Getting the commandline
    bpf_probe_read(&e.commandline, sizeof(e.commandline),
                   (void *)PT_REGS_RC(ctx));

    // Submitting the event to the ring buffer
    bpf_perf_event_output(ctx, &bashReadlineEventMap, BPF_F_CURRENT_CPU, &e,
                          sizeof(e));

    return 0;
}
