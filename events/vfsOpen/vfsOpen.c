// events/vfsOpen/vfsOpen.c
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
// We extract the dentry from path, then traverse its d_parent chain.
SEC("kprobe/vfs_open")
int BPF_KPROBE(vfs_open, const struct path *path, struct file *file) {
    struct dentry *dentry = 0;
    const unsigned char *fname_ptr = 0;
    int i;

    // Read the initial dentry pointer from path->dentry.
    if (bpf_probe_read_kernel(&dentry, sizeof(struct dentry), &path->dentry) !=
        0) {
        return 0;
    }

    // Traverse up to 50 levels of parent dentries.
    // TODO: Later, we'll concatenate each filename into a full path.
    for (i = 0; i < 50 && dentry != NULL; i++) {
        struct file_create_event *e;

        // Reserve a new event for the current dentry.
        e = bpf_ringbuf_reserve(&vfsOpenEventMap, sizeof(*e), 0);
        if (!e)
            return 0;

        e->pid = bpf_get_current_pid_tgid() >> 32;
        e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

        // Read the filename pointer from dentry->d_name.name.
        if (bpf_probe_read_kernel(&fname_ptr, sizeof(fname_ptr),
                                  &dentry->d_name.name) != 0) {
            bpf_ringbuf_discard(e, 0);
            break;
        }

        // Copy the filename string into our event buffer.
        bpf_probe_read_kernel_str(e->filename, sizeof(e->filename), fname_ptr);

        // Discard if e->filename is "/"
        if (e->filename[0] == '/' && e->filename[1] == '\0') {
            bpf_ringbuf_discard(e, 0);
            break;
        }

        bpf_ringbuf_submit(e, 0);

        // Move to the parent dentry.
        if (bpf_probe_read_kernel(&dentry, sizeof(struct dentry),
                                  &dentry->d_parent) != 0) {
            break;
        }
    }

    return 0;
}
