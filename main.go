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
)

func main() {
	// Create a cancellable context.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start the fileCreate event collector.
	go func() {
		if err := fileCreate.Run(ctx); err != nil {
			log.Fatalf("fileCreate event collector error: %v", err)
		}
	}()

	// Listen for termination signals.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	fmt.Println("Event collectors running. Press Ctrl+C to exit.")

	<-sigCh
	fmt.Println("Termination signal received. Shutting down...")
	cancel()

	// Allow a moment for collectors to exit gracefully.
	time.Sleep(1 * time.Second)
}
