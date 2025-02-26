// events/vfsOpen/vfsOpen.c
// go:build ignore
#define __TARGET_ARCH_x86
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <limits.h>

// Use a weak license definition to avoid duplicate symbol issues.
char LICENSE[] SEC("license") __attribute__((weak)) = "GPL";

// Updated event structure: increased filepath buffer size.
struct file_create_event {
    __u32 uid;
    __u32 pid;
    __u32 flags;
    char filepathSegment[512];
    bool firstSegment; // True if this event is
                       // the first segment for a new path.
} __attribute__((packed));

// Create a ring buffer map for events.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB
} vfsOpenEventMap SEC(".maps");

// Attach to vfs_open.
// Prototype: int vfs_open(const struct path *path, struct file *file)
SEC("kprobe/vfs_open")
int BPF_KPROBE(vfs_open, const struct path *path, struct file *file) {
    struct dentry *dentry = 0;
    const unsigned char *fname_ptr = 0;

    // Read the initial dentry pointer from path->dentry.
    if (bpf_probe_read_kernel(&dentry, sizeof(dentry), // NOLINT
                              &path->dentry) != 0) {   // NOLINT
        return 0;
    }

    // Traverse up to 50 levels of parent dentries.
    // Each iteration sends one filepath segment (split by "/") to the ring
    // buffer. The full path is reassembled in user space.
    // (The limit of 50 is arbitrary and can be adjusted as needed.)
    for (unsigned int i = 0; i < 50 && dentry != NULL; i++) {
        struct file_create_event *e;

        // Reserve a new event for the current dentry.
        e = bpf_ringbuf_reserve(&vfsOpenEventMap, sizeof(*e), 0);
        if (!e)
            return 0;

        e->pid = bpf_get_current_pid_tgid() >> 32;
        e->uid = bpf_get_current_uid_gid() >> 32;

        // Mark the first segment of a new file path.
        if (i == 0) {
            e->firstSegment = true;
        } else {
            e->firstSegment = false;
        }

        // Read the filepath pointer from dentry->d_name.name.
        if (bpf_probe_read_kernel(&fname_ptr, sizeof(fname_ptr),
                                  &dentry->d_name.name) != 0) {
            bpf_ringbuf_discard(e, 0);
            break;
        }

        // Copy the filepath string into our event buffer.
        bpf_probe_read_kernel_str(e->filepathSegment,
                                  sizeof(e->filepathSegment), fname_ptr);

        // Discard if e->filename is "/" (meaningless information)
        if (e->filepathSegment[0] == '/' && e->filepathSegment[1] == '\0') {
            bpf_ringbuf_discard(e, 0);
            break;
        }

        // Get the current file's flag
        if (bpf_probe_read_kernel(&e->flags, sizeof(e->flags),
                                  &file->f_flags) != 0) {
            bpf_ringbuf_discard(e, 0);
            return 0;
        }

        bpf_ringbuf_submit(e, 0);

        // Move to the parent dentry.
        if (bpf_probe_read_kernel(&dentry, sizeof(dentry),   // NOLINT
                                  &dentry->d_parent) != 0) { // NOLINT
            break;
        }
    }

    return 0;
}
