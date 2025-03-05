// events/tcpV4Accept/tcpV4Accept.c
// go: build ignore
#define __TARGET_ARCH_x86
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// Macro-defined functions to handle network/system endianness.
#define ___bpf_mvb(x, b, n, m)                                                 \
    ((__u##b)(x) << (b - (n + 1) * 8) >> (b - 8) << (m * 8))
#define ___bpf_swab16(x)                                                       \
    ((__u16)(___bpf_mvb(x, 16, 0, 1) | ___bpf_mvb(x, 16, 1, 0)))
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define __bpf_ntohs(x) __builtin_bswap16(x)
#define __bpf_constant_ntohs(x) ___bpf_swab16(x)
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define __bpf_ntohs(x) (x)
#define __bpf_constant_ntohs(x) (x)
#else
#error "Fix your compiler's __BYTE_ORDER__?!"
#endif
#define bpf_ntohs(x)                                                           \
    (__builtin_constant_p(x) ? __bpf_constant_ntohs(x) : __bpf_ntohs(x))

char LICENSE[] SEC("license") __attribute__((weak)) = "GPL";

// Event structure for accepted TCPv4 connections.
struct tcp_v4_accept_event {
    __u32 pid;
    __u32 uid;
    __u32 sa_family;   // Address family (AF_INET)
    __u32 local_addr;  // Local (server) IPv4 address
    __u32 remote_addr; // Remote (client) IPv4 address
    __u16 local_port;  // Local port (server port)
    __u16 remote_port; // Remote port (client port)
} __attribute__((packed));

// Ring buffer map for delivering events to user space.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB.
} tcpV4AcceptEventMap SEC(".maps");

// Hash map to stash the listening sock pointer keyed by PID.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct sock *);
    __uint(max_entries, 10240);
} currsockTcpAccept SEC(".maps");

// kprobe: Triggered when inet_csk_accept is entered.
// Stash the listening socket pointer.
SEC("kprobe/inet_csk_accept")
int BPF_KPROBE(inet_csk_accept_entry, struct sock *sk, int flags, int *err) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_map_update_elem(&currsockTcpAccept, &pid, &sk, BPF_ANY);
    return 0;
}

// kretprobe: Triggered when inet_csk_accept returns.
// Retrieves the accepted sock pointer and extracts connection details.
SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(inet_csk_accept_ret) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct sock **skpp = bpf_map_lookup_elem(&currsockTcpAccept, &pid);
    if (!skpp)
        return 0;

    // Get the returned accepted sock pointer.
    struct sock *skp = (struct sock *)PT_REGS_RC(ctx);
    if ((unsigned long)skp < 4096) {
        bpf_map_delete_elem(&currsockTcpAccept, &pid);
        return 0;
    }

    struct tcp_v4_accept_event *e;
    e = bpf_ringbuf_reserve(&tcpV4AcceptEventMap, sizeof(*e), 0);
    if (!e) {
        bpf_map_delete_elem(&currsockTcpAccept, &pid);
        return 0;
    }

    e->pid = pid;
    e->uid = bpf_get_current_uid_gid() >> 32;

    // Read the accepted socket details.
    if (bpf_probe_read_kernel(&e->sa_family, sizeof(e->sa_family),
                              &skp->__sk_common.skc_family) < 0 ||
        bpf_probe_read_kernel(&e->local_addr, sizeof(e->local_addr),
                              &skp->__sk_common.skc_rcv_saddr) < 0 ||
        bpf_probe_read_kernel(&e->local_port, sizeof(e->local_port),
                              &skp->__sk_common.skc_num) < 0 ||
        bpf_probe_read_kernel(&e->remote_addr, sizeof(e->remote_addr),
                              &skp->__sk_common.skc_daddr) < 0 ||
        bpf_probe_read_kernel(&e->remote_port, sizeof(e->remote_port),
                              &skp->__sk_common.skc_dport) < 0) {
        bpf_ringbuf_discard(e, 0);
        bpf_map_delete_elem(&currsockTcpAccept, &pid);
        return 0;
    }

    // Convert port numbers from network to host byte order.
    e->local_port = bpf_ntohs(e->local_port);
    e->remote_port = bpf_ntohs(e->remote_port);

    bpf_ringbuf_submit(e, 0);
    bpf_map_delete_elem(&currsockTcpAccept, &pid);
    return 0;
}
