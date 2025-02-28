// TODO: This code should be moved into events/networkEvent/tcp/tcpConnect.c to
// be hierarchical.
//
// events/networkEvent/tcpConnect.c
// go:build ignore
#define __TARGET_ARCH_x86
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// Macro-defined functions to handle network/system endianness.
// Reference: https://docs.ebpf.io/ebpf-library/libbpf/ebpf/bpf_ntohs/
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

// Event structure for TCP connection events.
// All addresses/ports are in network byte order.
struct tcp_v4_connect_event {
    __u32 pid;
    __u32 uid;
    __u32 sa_family; // Socket family from sk->__sk_common.skc_family.
    __u32 saddr;     // Source IPv4 address.
    __u32 daddr;     // Destination IPv4 address.
    __u16 sport;     // Source port.
    __u16 dport;     // Destination port.
} __attribute__((packed));

// Ring buffer map for sending events to user space.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB.
} tcpV4ConnectEventMap SEC(".maps");

// Map to stash the sock pointer on entry.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct sock *);
    __uint(max_entries, 10240);
} currsock SEC(".maps");

// Called at the entry of tcp_v4_connect.
// If we observe a socket structure at kprobe(entry time), we'll see nothing,
// everything is zeroed out. We have to revisit the internal data at
// kretprobe(return time) again.
// It stores the sock pointer keyed by the current PID.
SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(tcp_v4_connect_entry, struct sock *sk) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_map_update_elem(&currsock, &pid, &sk, BPF_ANY);
    return 0;
}

// Called when tcp_v4_connect returns.
// It retrieves the sock pointer, checks the return value, and reads the
// populated fields.
SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(tcp_v4_connect_ret) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    int ret = PT_REGS_RC(ctx);

    // Lookup the stored sock pointer based on the PID(key).
    struct sock **skpp = bpf_map_lookup_elem(&currsock, &pid);
    if (!skpp)
        return 0;
    if (ret != 0) {
        // Connection failed; cleanup.
        bpf_map_delete_elem(&currsock, &pid);
        return 0;
    }

    struct sock *skp = *skpp;
    struct tcp_v4_connect_event *e;

    // Reserve space in the ring buffer.
    e = bpf_ringbuf_reserve(&tcpV4ConnectEventMap, sizeof(*e), 0);
    if (!e) {
        bpf_map_delete_elem(&currsock, &pid);
        return 0;
    }

    e->pid = pid;
    e->uid = bpf_get_current_uid_gid() >> 32;

    // Read kernel-side fields from the sock structure and obtain the
    // - socket family
    // - source address(IPv4) and source port
    // - destination address(IPv4) and destination port
    if (bpf_probe_read_kernel(&e->sa_family, sizeof(e->sa_family),
                              &skp->__sk_common.skc_family) < 0 ||
        bpf_probe_read_kernel(&e->saddr, sizeof(e->saddr),
                              &skp->__sk_common.skc_rcv_saddr) < 0 ||
        bpf_probe_read_kernel(&e->sport, sizeof(e->sport),
                              &skp->__sk_common.skc_num) < 0 ||
        bpf_probe_read_kernel(&e->daddr, sizeof(e->daddr),
                              &skp->__sk_common.skc_daddr) < 0 ||
        bpf_probe_read_kernel(&e->dport, sizeof(e->dport),
                              &skp->__sk_common.skc_dport) < 0) {
        bpf_ringbuf_discard(e, 0);
        bpf_map_delete_elem(&currsock, &pid);
        return 0;
    }

    // Convert the port numbers to host byte order.
    e->sport = bpf_ntohs(e->sport);
    e->dport = bpf_ntohs(e->dport);

    bpf_ringbuf_submit(e, 0);
    bpf_map_delete_elem(&currsock, &pid);
    return 0;
}
