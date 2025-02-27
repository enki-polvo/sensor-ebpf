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

	// "sensor-ebpf/events/fileCreate"
	"sensor-ebpf/events/fileDelete"
	"sensor-ebpf/events/processCreate"
	"sensor-ebpf/events/processTerminate"
	"sensor-ebpf/events/vfsOpen"
)

// startCollector is a generic helper function that sets up the event collector and processor.
// name: used for logging.
// runner: the event collector function (e.g., fileCreate.Run).
// handler: the function to process each event.
func startCollector[T any](
	ctx context.Context,
	name string,
	runner func(context.Context, chan<- T) error, // Accept send-only channel here.
	handler func(T),
) {
	ch := make(chan T, 10)

	// Start the collector.
	go func() {
		log.Printf("Starting %s event collector", name)
		if err := runner(ctx, ch); err != nil {
			log.Fatalf("%s event collector error: %v", name, err)
		}
	}()

	// Start the event processor.
	go func() {
		for event := range ch {
			handler(event)
		}
	}()
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start all collectors using the helper function.

	// NOTE: We temporarily disable the fileCreate collector because it we have kprobe:vfs_open instead
	// startCollector(ctx, "fileCreate", fileCreate.Run,
	// 	func(event fileCreate.FileCreateEvent) {
	// 		filepath := string(event.Filepath[:])
	// 		fmt.Printf("[sysFileCreate] PID: %d, UID: %d, Filepath: %s, Flags: %d, Mode: %d\n",
	// 			event.PID, event.UID, filepath, event.Flags, event.Mode)
	// 	})

	startCollector(ctx, "fileDelete", fileDelete.Run,
		func(event fileDelete.FileDeleteEvent) {
			fmt.Printf("[fileDelete] PID: %d, UID: %d, Filepath: %s, Flag: %d\n",
				event.PID, event.UID, event.Filepath, event.Flag)
		})

	startCollector(ctx, "processCreate", processCreate.Run,
		func(event processCreate.ProcessCreateEvent) {
			// Concatenate the parameters into a single string.
			parameterStrConcatenator := func(parameters [10][256]byte) string {
				result := ""
				for _, param := range parameters {
					result += fmt.Sprintf("%s ", string(param[:]))
				}
				return result
			}

			argsString := parameterStrConcatenator(event.Args)
			// envsString := parameterStrConcatenator(event.Envs)
			fmt.Printf("[sysProcessCreate] PID: %d, PPID: %d, TGID: %d, UID: %d, Command: %s, Filename: %s, Argv: %s\n",
				event.PID, event.PPID, event.TGID, event.UID, event.Command, event.Filename, argsString)
		})

	startCollector(ctx, "processTerminate", processTerminate.Run,
		// Convert event.Cmd([512]bytes) into hexadecimalized string
		func(event processTerminate.ProcessTerminateEvent) {
			fmt.Printf("[sysProcessTerminate] PID: %d, UID: %d, Cmdline: %s, Ret: %d\n", event.PID, event.UID, event.Cmdline, event.Ret)
		})

	startCollector(ctx, "vfsOpen", vfsOpen.Run,
		func(event vfsOpen.VfsOpenFullEvent) {
			// fmt.Printf("[vfsOpen] PID: %d, UID: %d, Full Filepath: %s, Flags: %O(%v)\n",
			// 	event.PID, event.UID, event.FullPath, event.Flags, event.FlagsInterpretation)
		})

	// Wait for termination signal.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	fmt.Println("Event collectors running. Press Ctrl+C to exit.")
	<-sigCh

	fmt.Println("Termination signal received. Shutting down...")
	cancel()
	time.Sleep(1 * time.Second) // Allow time for graceful shutdown.
}
