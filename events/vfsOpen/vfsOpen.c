// go:build ignore
#define __TARGET_ARCH_x86
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// Use a weak license definition to avoid duplicate symbol issues.
char LICENSE[] SEC("license") __attribute__((weak)) = "GPL";

// Updated event structure: increased filename buffer size.
struct file_create_event {
    __u32 uid;
    __u32 pid;
    char filename[256];
} __attribute__((packed));

// Create a ring buffer map for events.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB
} vfsOpenEventMap SEC(".maps");

// Attach to vfs_open.
// Prototype: int vfs_open(const struct path *path, struct file *file)
// We extract the dentry from path, then get the file name from
// dentry->d_name.name.
SEC("kprobe/vfs_open")
int BPF_KPROBE(vfs_open, const struct path *path, struct file *file) {
    struct file_create_event *e;
    const struct dentry *dentry = 0;
    const unsigned char *fname_ptr = 0;

    e = bpf_ringbuf_reserve(&vfsOpenEventMap, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    // Read the dentry pointer from path->dentry.
    if (bpf_probe_read_kernel(&dentry, sizeof(dentry), &path->dentry) != 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    // Read the filename pointer from dentry->d_name.name.
    if (bpf_probe_read_kernel(&fname_ptr, sizeof(fname_ptr),
                              &dentry->d_name.name) != 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    // Copy the filename from the pointer into our event buffer.
    bpf_probe_read_kernel_str(e->filename, sizeof(e->filename), fname_ptr);

    bpf_ringbuf_submit(e, 0);
    return 0;
}
