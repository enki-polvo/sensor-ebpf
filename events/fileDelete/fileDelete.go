// events/fileDelete/fileDelete.go
package fileDelete

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

type FileDeleteEvent struct {
	UID       uint32
	PID       uint32
	EventType uint8 // 0 for unlink, 1 for unlinkat
	Filepath  [512]byte
	Flag      int32
}

// Run starts the file delete event collector and sends events over the provided channel.
// It closes the channel when exiting.
func Run(ctx context.Context, events chan<- FileDeleteEvent) error {
	// Remove resource limits.
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("failed to remove memlock limit: %w", err)
	}

	// Load pre-compiled BPF objects.
	objs := fileDeleteObjects{}
	if err := loadFileDeleteObjects(&objs, nil); err != nil {
		return fmt.Errorf("loading objects: %w", err)
	}
	defer objs.Close()

	// Attach tracepoint for sys_enter_unlink.
	tpUnlink, err := link.Tracepoint("syscalls", "sys_enter_unlink", objs.TraceSysEnterUnlink, nil)
	if err != nil {
		return fmt.Errorf("failed to attach tracepoint sys_enter_unlink: %w", err)
	}
	defer tpUnlink.Close()

	// Attach tracepoint for sys_enter_unlinkat.
	tpUnlinkat, err := link.Tracepoint("syscalls", "sys_enter_unlinkat", objs.TraceSysEnterUnlinkat, nil)
	if err != nil {
		return fmt.Errorf("failed to attach tracepoint sys_enter_unlinkat: %w", err)
	}
	defer tpUnlinkat.Close()

	// Open a ring buffer reader on the map.
	rd, err := ringbuf.NewReader(objs.FileDeleteEventMap)
	if err != nil {
		return fmt.Errorf("failed to open ring buffer: %w", err)
	}
	defer rd.Close()

	log.Println("Starting fileDelete event collector")
	// Ensure the channel gets closed once Run exits.
	defer close(events)

	var event FileDeleteEvent
	for {
		select {
		case <-ctx.Done():
			log.Println("file delete event collector stopping")
			return nil
		default:
			// Read the next event.
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

			// Instead of printing, send the event over the channel.
			select {
			case events <- event:
				// Event sent.
			case <-ctx.Done():
				return nil
			}
		}
	}
}
