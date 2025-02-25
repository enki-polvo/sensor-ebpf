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
	"sensor-ebpf/events/vfsOpen"
)

func main() {
	// Create a cancellable context.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create buffered channels for events.
	sysFileCreateEventCh := make(chan fileCreate.FileCreateEvent, 10)
	kprobeVfsOpenEventCh := make(chan vfsOpen.FileCreateEvent, 10)

	// Start the sysFileCreate event collector.
	go func() {
		if err := fileCreate.Run(ctx, sysFileCreateEventCh); err != nil {
			log.Fatalf("fileCreate event collector error: %v", err)
		}
	}()

	// Start the vfsOpen event collector.
	go func() {
		if err := vfsOpen.Run(ctx, kprobeVfsOpenEventCh); err != nil {
			log.Fatalf("vfsOpen event collector error: %v", err)
		}
	}()

	// Process sysFileCreate events.
	go func() {
		for event := range sysFileCreateEventCh {
			filepath := string(bytes.Trim(event.Filepath[:], "\x00"))
			fmt.Printf("[sysFileCreate] PID: %d, UID: %d, Filepath: %s, Flags: %d, Mode: %d\n",
				event.PID, event.UID, filepath, event.Flags, event.Mode)
		}
	}()

	// Process vfsOpen events.
	go func() {
		for event := range kprobeVfsOpenEventCh {
			filepath := string(bytes.Trim(event.Filepath[:], "\x00"))
			fmt.Printf("[vfsOpen] PID: %d, UID: %d, Filepath: %s\n",
				event.PID, event.UID, filepath)
		}
	}()

	// Listen for termination signals.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	fmt.Println("Event collectors running. Press Ctrl+C to exit.")
	<-sigCh
	fmt.Println("Termination signal received. Shutting down...")
	cancel()

	// Allow time for collectors to exit gracefully.
	time.Sleep(1 * time.Second)
}
