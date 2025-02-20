package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall" bpf fileCreate.c -- -I/path/to/vmlinux/headers

// fileCreateEvent matches the struct file_create_event in our BPF program.
type fileCreateEvent struct {
	UID       uint32
	PID       uint32
	Filename  [256]byte
	Flags     int32
	Mode      uint32
	EventType uint32 // 1: open, 2: openat
}

func main() {
	// Remove resource limits.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock limit: %v", err)
	}

	// Load pre-compiled BPF objects.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// Attach tracepoints.
	tpOpenat, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.TraceSysEnterOpenat, nil)
	if err != nil {
		log.Fatalf("Failed to attach tracepoint sys_enter_openat: %v", err)
	}
	defer tpOpenat.Close()

	tpOpen, err := link.Tracepoint("syscalls", "sys_enter_open", objs.TraceSysEnterOpen, nil)
	if err != nil {
		log.Fatalf("Failed to attach tracepoint sys_enter_open: %v", err)
	}
	defer tpOpen.Close()

	// Open a ring buffer reader on the map.
	rd, err := ringbuf.NewReader(objs.FileCreateEventMap)
	if err != nil {
		log.Fatalf("Failed to open ring buffer: %v", err)
	}
	defer rd.Close()

	// Setup signal handling for graceful exit.
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stopper
		rd.Close()
	}()

	log.Println("Listening for file create events (open and openat). Press Ctrl+C to exit.")

	var event fileCreateEvent
	for {
		// Read the next event.
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("Exiting...")
				return
			}
			log.Printf("Error reading from ring buffer: %v", err)
			continue
		}

		// Parse the event.
		err = binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event)
		if err != nil {
			log.Printf("Error parsing event: %v", err)
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
