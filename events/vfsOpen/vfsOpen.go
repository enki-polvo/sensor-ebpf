// events/vfsOpen/vfsOpen.go
package vfsOpen

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// FileCreateEvent matches the simplified struct file_create_event from our BPF program.
type FileCreateEvent struct {
	UID      uint32
	PID      uint32
	Filename [256]byte
}

// Run starts the vfs_open kprobe, reads events from the ring buffer, and sends them over the provided channel.
func Run(ctx context.Context, events chan<- FileCreateEvent) error {
	// Remove memlock limits.
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("failed to remove memlock: %w", err)
	}

	// Load pre-compiled BPF objects. This assumes you've generated them using bpf2go.
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

	log.Println("Listening for vfs_open events...")
	defer close(events)

	var event FileCreateEvent
	for {
		select {
		case <-ctx.Done():
			log.Println("vfsOpen event collector stopping")
			return nil
		default:
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					log.Println("ring buffer closed, exiting")
					return nil
				}
				log.Printf("error reading from ring buffer: %v", err)
				continue
			}

			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
				log.Printf("error parsing event: %v", err)
				continue
			}

			select {
			case events <- event:
			case <-ctx.Done():
				return nil
			}
		}
	}
}
