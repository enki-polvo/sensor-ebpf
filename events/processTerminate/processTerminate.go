// events/processTerminate/processTerminate.go
package processTerminate

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

type ProcessTerminateEventOriginal struct {
	UID     uint32
	PID     uint32
	Ret     uint64 // Ret is defined as "long" in the kernel, which is 64-bit on x86_64 Linux.
	Cmdline [512]byte
}

type ProcessTerminateEvent struct {
	UID     uint32
	PID     uint32
	Ret     uint64 // Ret is defined as "long" in the kernel, which is 64-bit on x86_64 Linux.
	Cmdline string // String representation of the command line.
}

// Run starts the ProcessTerminate event collector and sends events over the provided channel.
// It closes the channel when exiting.
func Run(ctx context.Context, events chan<- ProcessTerminateEvent) error {
	// Remove resource limits.
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("failed to remove memlock limit: %w", err)
	}

	// Load pre-compiled BPF objects.
	objs := processTerminateObjects{}
	if err := loadProcessTerminateObjects(&objs, nil); err != nil {
		return fmt.Errorf("failed to load BPF objects: %w", err)
	}
	defer objs.Close()

	// Attach tracepoints.
	tpExecveExit, err := link.Tracepoint("syscalls", "sys_exit_execve", objs.TraceSysExitExecve, nil)
	if err != nil {
		return fmt.Errorf("failed to attach tracepoint sys_exit_execve: %w", err)
	}
	defer tpExecveExit.Close()

	tpExecveatExit, err := link.Tracepoint("syscalls", "sys_exit_execveat", objs.TraceSysExitExecveat, nil)
	if err != nil {
		return fmt.Errorf("failed to attach tracepoint sys_exit_execveat: %w", err)
	}
	defer tpExecveatExit.Close()

	// Open a ring buffer reader on the map.
	rd, err := ringbuf.NewReader(objs.ProcessTerminateEventMap)
	if err != nil {
		return fmt.Errorf("failed to open ringbuf reader: %w", err)
	}
	defer rd.Close()

	// Ensure the channel gets closed once Run exits.
	log.Println("Listening for process termination events (tracepoint/syscalls/sys_exit_execve, tracepoint/syscalls/sys_exit_execveat).")
	defer close(events)

	var eventOriginal ProcessTerminateEventOriginal
	for {
		select {
		case <-ctx.Done():
			log.Println("Exiting process termination event collector")
			return nil
		default:
			// Read the next event.
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					log.Println("Ring buffer closed, exiting")
					return nil
				}
				log.Printf("Failed to read ring buffer: %v", err)
				continue
			}

			// Parse the event.
			err = binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &eventOriginal)
			if err != nil {
				log.Printf("Failed to parse event: %v", err)
				continue
			}

			// Convert the fixed-size byte array to a string and trim trailing nulls/spaces.
			raw := eventOriginal.Cmdline[:]
			// Do the right trim the null and space characters.
			s := strings.TrimRight(string(raw), "\x00")
			s = strings.TrimRight(s, " ")

			event := ProcessTerminateEvent{
				UID:     eventOriginal.UID,
				PID:     eventOriginal.PID,
				Ret:     eventOriginal.Ret,
				Cmdline: s,
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
