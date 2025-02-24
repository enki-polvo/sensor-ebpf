// main.go
package main

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"sensor-ebpf/events/fileCreate"
	"sensor-ebpf/events/vfsCreate"
)

func main() {
	// Create a cancellable context.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create buffered channels for events.
	sysFileCreateEventCh := make(chan fileCreate.FileCreateEvent, 10)
	kprobeFileCreateEventCh := make(chan vfsCreate.FileCreateEvent, 10)

	// Start the sysFileCreate event collector.
	go func() {
		if err := fileCreate.Run(ctx, sysFileCreateEventCh); err != nil {
			log.Fatalf("fileCreate event collector error: %v", err)
		}
	}()

	// Start the vfsCreate event collector.
	go func() {
		if err := vfsCreate.Run(ctx, kprobeFileCreateEventCh); err != nil {
			log.Fatalf("vfsCreate event collector error: %v", err)
		}
	}()

	// Start a goroutine to process sysFileCreate events.
	go func() {
		for event := range sysFileCreateEventCh {
			// Trim the null bytes from the filename.
			filename := string(bytes.Trim(event.Filename[:], "\x00"))
			fmt.Printf("[sysFileCreate] PID: %d, UID: %d, Filename: %s, Flags: %d, Mode: %d\n",
				event.PID, event.UID, filename, event.Flags, event.Mode)
		}
	}()

	// Start a goroutine to process vfsCreate events.
	go func() {
		for event := range kprobeFileCreateEventCh {
			fmt.Println("There is an event")
			filename := string(bytes.Trim(event.Filename[:], "\x00"))
			fmt.Printf("[vfsCreate] PID: %d, UID: %d, Filename: %s, Flags: %d, Mode: %d\n",
				event.PID, event.UID, filename, event.Flags, event.Mode)
		}
	}()

	// Listen for termination signals.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	fmt.Println("Event collectors running. Press Ctrl+C to exit.")

	// Block until a termination signal is received.
	<-sigCh
	fmt.Println("Termination signal received. Shutting down...")
	cancel()

	// Allow a moment for collectors to exit gracefully.
	time.Sleep(1 * time.Second)
}
