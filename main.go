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
	"sensor-ebpf/events/processCreate"
	"sensor-ebpf/events/vfsOpen"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Channels listening to the events.
	sysFileCreateEventCh := make(chan fileCreate.FileCreateEvent, 10)
	sysProcessCreateEventCh := make(chan processCreate.ProcessCreateEvent, 10)
	kprobeVfsOpenEventCh := make(chan vfsOpen.VfsOpenFullEvent, 10)

	// Start the sysFileCreate event collector.
	go func() {
		log.Println("Starting fileCreate event collector")
		if err := fileCreate.Run(ctx, sysFileCreateEventCh); err != nil {
			log.Fatalf("fileCreate event collector error: %v", err)
		}
	}()

	// Start the sysProcessCreate event collector.
	go func() {
		log.Println("Starting processCreate event collector")
		if err := processCreate.Run(ctx, sysProcessCreateEventCh); err != nil {
			log.Fatalf("processCreate event collector error: %v", err)
		}
	}()

	// Start the vfsOpen event collector.
	go func() {
		log.Println("Starting vfsOpen event collector")
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

	// Process sysProcessCreate events.
	go func() {
		for event := range sysProcessCreateEventCh {
			fmt.Printf("[sysProcessCreate] PID: %d, UID: %d, Command: %s, Filename: %s, Argc: %d, Envc: %d\n",
				event.PID, event.UID, event.Command, event.Filename, event.Argc, event.Envc)
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
