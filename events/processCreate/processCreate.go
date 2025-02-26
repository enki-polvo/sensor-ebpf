// events/fileCreate/processCreate.c
package processCreate

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

type ProcessCreateEvent struct {
	UID      uint32
	PID      uint32
	PPID     uint32
	Command  [16]byte
	Filename [256]byte
	Argc     uint32
	Envc     uint32
	Args     [10][256]byte
	Envs     [10][256]byte
}

// Run starts the fileCreate event collector and sends events over the provided channel.
// It closes the channel when exiting.
func Run(ctx context.Context, events chan<- ProcessCreateEvent) error {
	// Remove resource limits.
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("failed to remove memlock limit: %w", err)
	}

	// Load pre-compiled BPF objects.
	objs := processCreateObjects{}
	if err := loadProcessCreateObjects(&objs, nil); err != nil {
		return fmt.Errorf("failed to load BPF objects: %w", err)
	}
	defer objs.Close()

	// Attach tracepoints
	tpExecve, err := link.Tracepoint("syscalls", "sys_enter_execve",
		objs.TraceSysEnterExecve, nil)
	if err != nil {
		return fmt.Errorf("failed to attach tracepoint sys_enter_execve: %w", err)
	}
	defer tpExecve.Close()

	tpExecveat, err := link.Tracepoint("syscalls", "sys_enter_execveat",
		objs.TraceSysEnterExecveat, nil)
	if err != nil {
		return fmt.Errorf("failed to attach tracepoint sys_enter_execveat: %w", err)
	}
	defer tpExecveat.Close()

	// Open a ring buffer reader on the map
	rd, err := ringbuf.NewReader(objs.ProcessCreateEventMap)
	if err != nil {
		return fmt.Errorf("failed to open ringbuf reader: %w", err)
	}
	defer rd.Close()

	// Ensure the channel gets closed once Run exits.
	defer close(events)

	var event ProcessCreateEvent
	for {
		select {
		case <-ctx.Done():
			log.Println("Exiting process create event collector")
			return nil
		default:
			// Read the next event
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					log.Println("Ring buffer closed, exiting")
					return nil
				}
				log.Printf("Failed to read ring buffer: %v", err)
				continue
			}

			// Parse the even t
			err = binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event)
			if err != nil {
				log.Printf("Failed to parse event: %v", err)
				continue
			}

			// Instead of printing the event, send it over the channeel
			select {
			case events <- event:
				// Sent successfully
			case <-ctx.Done():
				return nil
			}
		}
	}
}
