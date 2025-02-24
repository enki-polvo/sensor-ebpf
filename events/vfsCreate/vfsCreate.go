// sensors/vfsCreate/vfsCreate.go
package vfsCreate

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

// FileCreateEvent matches the struct file_create_event in our BPF program.
type FileCreateEvent struct {
	UID      uint32
	PID      uint32
	Filename [256]byte
	Flags    int32
	Mode     uint32
}

// Run starts the vfs_create kprobe, reads events from the ring buffer, and sends them over the provided channel.
func Run(ctx context.Context, events chan<- FileCreateEvent) error {
	// Remove resource limits so we can load our BPF objects.
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("failed to remove memlock: %w", err)
	}

	// Load pre-compiled BPF objects.
	objs := vfsCreateObjects{}
	if err := loadVfsCreateObjects(&objs, nil); err != nil {
		return fmt.Errorf("loading objects: %w", err)
	}
	defer objs.Close()

	// Attach the kprobe to vfs_create.
	kp, err := link.Kprobe("vfs_create", objs.VfsCreate, nil)
	if err != nil {
		return fmt.Errorf("failed to attach kprobe: %w", err)
	}
	defer kp.Close()

	// Open a ring buffer reader on the map.
	rd, err := ringbuf.NewReader(objs.VfsCreateEventMap)
	if err != nil {
		return fmt.Errorf("failed to open ring buffer: %w", err)
	}
	defer rd.Close()

	log.Println("Listening for vfs_create events...")
	// Close the event channel when exiting.
	defer close(events)

	var event FileCreateEvent
	for {
		select {
		case <-ctx.Done():
			log.Println("vfsCreate event collector stopping")
			return nil
		default:
			// Read the next event from the ring buffer.
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					log.Println("ring buffer closed, exiting")
					return nil
				}
				log.Printf("error reading from ring buffer: %v", err)
				continue
			}

			// Parse the event.
			err = binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event)
			if err != nil {
				log.Printf("error parsing event: %v", err)
				continue
			}

			// Send the event over the channel.
			select {
			case events <- event:
				// Sent successfully.
			case <-ctx.Done():
				return nil
			}
		}
	}
}
