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
)

func main() {
	// Create a cancellable context.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create a buffered channel for events.
	// TODO: Generalize the event channel(s) so that we can use a single collector for multiple event types.
	//       (Or utilize multiple collectors, one for each event type.)
	fileCreateEventCh := make(chan fileCreate.FileCreateEvent, 10)

	// Start the fileCreate event collector.
	go func() {
		if err := fileCreate.Run(ctx, fileCreateEventCh); err != nil {
			log.Fatalf("fileCreate event collector error: %v", err)
		}
	}()

	// Listen for termination signals.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Start a goroutine to process and print events.
	go func() {
		for event := range fileCreateEventCh {
			filename := string(event.Filename[:])
			// TODO: Use povlo-logger to uniformly manage the log events.
			fmt.Printf("PID: %d, UID: %d, Filename: %s, Flags: %d, Mode: %d\n",
				event.PID, event.UID, filename, event.Flags, event.Mode)
		}
	}()

	fmt.Println("Event collectors running. Press Ctrl+C to exit.")

	<-sigCh
	fmt.Println("Termination signal received. Shutting down...")
	cancel()

	// Allow a moment for collectors to exit gracefully.
	time.Sleep(1 * time.Second)
}
