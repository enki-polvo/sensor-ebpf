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

// fileCreateEvent matches the struct file_create_event in our BPF program.
type fileCreateEvent struct {
	UID       uint32
	PID       uint32
	Filename  [256]byte
	Flags     int32
	Mode      uint32
	EventType uint32 // 1: open, 2: openat
}

// Run starts the fileCreate event collector and runs until the context is cancelled.
func Run(ctx context.Context) error {
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

	var event fileCreateEvent
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

			// Convert the filename by trimming any trailing nulls.
			filename := string(event.Filename[:])
			syscallName := "open"
			if event.EventType == 2 {
				syscallName = "openat"
			}

			fmt.Printf("PID: %d, UID: %d, Syscall: %s, Filename: %s, Flags: %d, Mode: %d\n",
				event.PID, event.UID, syscallName, filename, event.Flags, event.Mode)
		}
	}
}
