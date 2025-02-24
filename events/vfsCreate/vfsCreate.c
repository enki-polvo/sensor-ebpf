// go:build ignore
#define __TARGET_ARCH_x86
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") __attribute__((weak)) = "GPL";

// Event structure to be sent to userspace.
// Marked as packed to ensure identical memory layout between C and Go.
struct file_create_event {
    __u32 uid;
    __u32 pid;
    char filename[256];
    long flags;
    unsigned long mode;
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB
} vfsCreateEventMap SEC(".maps");

// Reference: https://elixir.bootlin.com/linux/v6.13.4/source/fs/namei.c#L3316
SEC("kprobe/vfs_create")
int BPF_KPROBE(vfs_create, struct mnt_idmap *idmap, struct inode *dir,
               struct dentry *dentry, umode_t mode, bool want_excl) {
    struct file_create_event *e;

    // Reserve space in the ring buffer.
    e = bpf_ringbuf_reserve(&vfsCreateEventMap,
                            sizeof(struct file_create_event), 0);
    if (!e)
        return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("vfs_create probe triggered\n");

    e->uid = bpf_get_current_uid_gid() >> 32;
    e->mode = mode;
    e->flags = want_excl; // "want_excl" often serves as a flag.

    // Extract the filename from the dentry. The dentry structure contains a
    // 'd_name' field, which in turn contains the 'name' pointer.
    // const char *name_ptr = NULL;
    // if (bpf_probe_read_kernel(&name_ptr, sizeof(name_ptr),
    //                           &dentry->d_name.name) != 0)
    //     return 0;
    // if (!name_ptr)
    //     return 0;
    // bpf_probe_read_str(e->filename, sizeof(e->filename), name_ptr);

    // Test: Just copy string "abc" to e->filename
    __builtin_memcpy(e->filename, "abc", 4);

    bpf_ringbuf_submit(e, 0);

    return 0;
}
