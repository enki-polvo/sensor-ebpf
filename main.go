// main.go
package main

import (
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
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Channel for sysFileCreate events (unchanged).
	sysFileCreateEventCh := make(chan fileCreate.FileCreateEvent, 10)
	// New channel for fully reassembled vfsOpen events.
	kprobeVfsOpenEventCh := make(chan vfsOpen.VfsOpenFullEvent, 10)

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
			filepath := string(event.Filepath[:])
			fmt.Printf("[sysFileCreate] PID: %d, UID: %d, Filepath: %s, Flags: %d, Mode: %d\n",
				event.PID, event.UID, filepath, event.Flags, event.Mode)
		}
	}()

	// Process vfsOpen events, printing the full reassembled file path.
	go func() {
		for event := range kprobeVfsOpenEventCh {
			fmt.Printf("[vfsOpen] PID: %d, UID: %d, Full Filepath: %s\n",
				event.PID, event.UID, event.FullPath)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	fmt.Println("Event collectors running. Press Ctrl+C to exit.")
	<-sigCh
	fmt.Println("Termination signal received. Shutting down...")
	cancel()

	// Allow time for collectors to exit gracefully.
	time.Sleep(1 * time.Second)
}
