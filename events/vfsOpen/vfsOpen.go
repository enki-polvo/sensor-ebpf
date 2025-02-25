// events/vfsOpen/vfsOpen.go
package vfsOpen

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// FileCreateEvent matches the kernel struct file_create_event.
// Due to the technical limitations of eBPF about the stack size limit(~512 bytes),
// We need to split the file path into segments and send them to user space.
type FileCreateEvent struct {
	UID             uint32
	PID             uint32
	FilepathSegment [512]byte
	FirstSegment    bool
}

// VfsOpenFullEvent is the event that carries the fully reassembled file path.
// Since Go program is outside of the kernel, we can reassemble the file path
// without the stack size limit.
type VfsOpenFullEvent struct {
	UID      uint32
	PID      uint32
	FullPath string
}

// Run starts the vfs_open kprobe, reads events from the ring buffer,
// reassembles the full file path from the received segments, and sends
// the fully assembled event over the provided channel.
func Run(ctx context.Context, events chan<- VfsOpenFullEvent) error {
	// Remove memlock limits.
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("failed to remove memlock: %w", err)
	}

	// Load pre-compiled BPF objects (assumes bpf2go has generated these).
	objs := vfsOpenObjects{}
	if err := loadVfsOpenObjects(&objs, nil); err != nil {
		return fmt.Errorf("loading objects: %w", err)
	}
	defer objs.Close()

	// Attach the kprobe to vfs_open.
	kp, err := link.Kprobe("vfs_open", objs.VfsOpen, nil)
	if err != nil {
		return fmt.Errorf("failed to attach kprobe: %w", err)
	}
	defer kp.Close()

	// Open a ring buffer reader on the map.
	rd, err := ringbuf.NewReader(objs.VfsOpenEventMap)
	if err != nil {
		return fmt.Errorf("failed to open ring buffer: %w", err)
	}
	defer rd.Close()

	// segmentChain accumulates the file path segments.
	var segmentChain []string
	var lastUID, lastPID uint32

	// Close the ring buffer reader and flush any remaining segments.
	flushChain := func() {
		if len(segmentChain) > 0 {
			// If there are any segments left when the new event(new filepath-related) arrives,
			// We reaseemble the path and send it to the user space immediately.
			fullPath := reassemblePath(segmentChain)
			events <- VfsOpenFullEvent{
				UID:      lastUID,
				PID:      lastPID,
				FullPath: fullPath,
			}
			// Since the segments are sent to the user space, we need to clear the segmentChain.
			segmentChain = segmentChain[:0]
		}
	}

	var event FileCreateEvent
	for {
		select {
		case <-ctx.Done():
			flushChain()
			return nil
		default:
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					flushChain()
					return nil
				}
				continue
			}

			if err := binary.Read(bytes.NewBuffer(record.RawSample),
				binary.LittleEndian, &event); err != nil {
				continue
			}

			// When a new file path starts, flush any accumulated segments.
			if event.FirstSegment {
				flushChain()
			}

			// Append this segment (trimming null bytes).
			seg := string(bytes.Trim(event.FilepathSegment[:], "\x00"))
			segmentChain = append(segmentChain, seg)
			lastUID = event.UID
			lastPID = event.PID
		}
	}
}

// reassemblePath takes a slice of path segments (in leaf-first order)
// and returns a full absolute path by reversing their order and joining them.
func reassemblePath(segments []string) string {
	// Create a new slice to hold segments in the correct (root-first) order.
	reversed := make([]string, 0, len(segments))

	// Loop from the end of the original slice to the beginning.
	for i := len(segments) - 1; i >= 0; i-- {
		reversed = append(reversed, segments[i])
	}

	// Join the reversed segments with "/" and prepend "/" to form an absolute path.
	fullPath := "/" + strings.Join(reversed, "/")
	return fullPath
}
