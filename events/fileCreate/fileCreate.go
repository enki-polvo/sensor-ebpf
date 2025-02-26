// events/fileCreate/fileCreate.go
package fileCreate

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
	Filepath [512]byte
	Flags    int32
	Mode     uint32
}

// Run starts the fileCreate event collector and sends events over the provided channel.
// It closes the channel when exiting.
func Run(ctx context.Context, events chan<- FileCreateEvent) error {
	// Remove resource limits.
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("failed to remove memlock limit: %w", err)
	}

	// Load pre-compiled BPF objects.
	objs := fileCreateObjects{}
	if err := loadFileCreateObjects(&objs, nil); err != nil {
		return fmt.Errorf("loading objects: %w", err)
	}
	defer objs.Close()

	// Attach tracepoints.
	tpOpenat, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.TraceSysEnterOpenat, nil)
	if err != nil {
		return fmt.Errorf("failed to attach tracepoint sys_enter_openat: %w", err)
	}
	defer tpOpenat.Close()

	tpOpen, err := link.Tracepoint("syscalls", "sys_enter_open", objs.TraceSysEnterOpen, nil)
	if err != nil {
		return fmt.Errorf("failed to attach tracepoint sys_enter_open: %w", err)
	}
	defer tpOpen.Close()

	// Open a ring buffer reader on the map.
	rd, err := ringbuf.NewReader(objs.FileCreateEventMap)
	if err != nil {
		return fmt.Errorf("failed to open ring buffer: %w", err)
	}
	defer rd.Close()

	log.Println("Listening for file create events (open and openat).")
	// Ensure the channel gets closed once Run exits.
	defer close(events)

	var event FileCreateEvent
	for {
		select {
		case <-ctx.Done():
			log.Println("fileCreate event collector stopping")
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
				// Sent successfully.
			case <-ctx.Done():
				return nil
			}
		}
	}
}
