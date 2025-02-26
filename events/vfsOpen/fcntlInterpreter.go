// events/vfsOpen/fcntlInterpreter.go
package vfsOpen

// For reference about the file flags(struct file->f_flags(unsigned int)), you can refer to fcntl.h of linux,
// https://github.com/torvalds/linux/blob/master/include/uapi/asm-generic/fcntl.h
const (
	O_ACCMODE   = 0o0000003
	O_RDONLY    = 0o0000000
	O_WRONLY    = 0o0000001
	O_RDWR      = 0o0000002
	O_CREAT     = 0o0000100
	O_EXCL      = 0o0000200
	O_NOCTTY    = 0o0000400
	O_TRUNC     = 0o0001000
	O_APPEND    = 0o0002000
	O_NONBLOCK  = 0o0004000
	O_DSYNC     = 0o0010000
	FASYNC      = 0o0020000
	O_DIRECT    = 0o0040000
	O_LARGEFILE = 0o0100000
	O_DIRECTORY = 0o0200000
	O_NOFOLLOW  = 0o0400000
	O_NOATIME   = 0o1000000
	O_CLOEXEC   = 0o2000000
)

// interpretFlags takes a numeric flag (which may be a compound value)
// and returns the corresponding flag names.
func InterpretFileFlags(flags uint32) []string {
	var meanings []string

	// Handle access mode separately.
	switch flags & O_ACCMODE {
	case O_RDONLY:
		meanings = append(meanings, "O_RDONLY")
	case O_WRONLY:
		meanings = append(meanings, "O_WRONLY")
	case O_RDWR:
		meanings = append(meanings, "O_RDWR")
	}

	// List of non-mutually exclusive flags.
	flagList := []struct {
		mask uint32
		name string
	}{
		{O_CREAT, "O_CREAT"},
		{O_EXCL, "O_EXCL"},
		{O_NOCTTY, "O_NOCTTY"},
		{O_TRUNC, "O_TRUNC"},
		{O_APPEND, "O_APPEND"},
		{O_NONBLOCK, "O_NONBLOCK"},
		{O_DSYNC, "O_DSYNC"},
		{FASYNC, "FASYNC"},
		{O_DIRECT, "O_DIRECT"},
		{O_LARGEFILE, "O_LARGEFILE"},
		{O_DIRECTORY, "O_DIRECTORY"},
		{O_NOFOLLOW, "O_NOFOLLOW"},
		{O_NOATIME, "O_NOATIME"},
		{O_CLOEXEC, "O_CLOEXEC"},
	}

	for _, flag := range flagList {
		if flags&flag.mask != 0 {
			meanings = append(meanings, flag.name)
		}
	}

	return meanings
}
