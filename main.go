// main.go
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/charmbracelet/huh"
	"sensor-ebpf/events/fileCreate"
	"sensor-ebpf/events/fileDelete"
	"sensor-ebpf/events/processCreate"
	"sensor-ebpf/events/processTerminate"
	"sensor-ebpf/events/vfsOpen"
)

// startCollector is a generic helper that sets up an event collector and processor.
func startCollector[T any](
	ctx context.Context,
	name string,
	runner func(context.Context, chan<- T) error,
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
	// Use huh? to interactively ask which collectors to run.
	var collectors []string
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewMultiSelect[string]().
				Title("Select collectors to run (minimum 1, maximum all)").
				Options(
					huh.NewOption("fileCreate", "fileCreate"),
					huh.NewOption("fileDelete", "fileDelete"),
					huh.NewOption("processCreate", "processCreate"),
					huh.NewOption("processTerminate", "processTerminate"),
					huh.NewOption("vfsOpen", "vfsOpen"),
				).
				Value(&collectors).
				// Validate that at least one collector is chosen.
				Validate(func(selected []string) error {
					if len(selected) < 1 {
						return errors.New("please select at least one collector")
					}
					return nil
				}),
		),
	)

	if err := form.Run(); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("You selected: %v\n", collectors)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start only the collectors that were selected.
	for _, c := range collectors {
		switch c {
		case "fileCreate":
			startCollector(ctx, "fileCreate", fileCreate.Run,
				func(event fileCreate.FileCreateEvent) {
					filepath := string(event.Filepath[:])
					fmt.Printf("[fileCreate] PID: %d, UID: %d, Filepath: %s, Flags: %d, Mode: %d\n",
						event.PID, event.UID, filepath, event.Flags, event.Mode)
				})
		case "fileDelete":
			startCollector(ctx, "fileDelete", fileDelete.Run,
				func(event fileDelete.FileDeleteEvent) {
					fmt.Printf("[fileDelete] PID: %d, UID: %d, Filepath: %s, Flag: %d\n",
						event.PID, event.UID, event.Filepath, event.Flag)
				})
		case "processCreate":
			startCollector(ctx, "processCreate", processCreate.Run,
				func(event processCreate.ProcessCreateEvent) {
					// Concatenate parameters into a string.
					parameterStr := func(params [10][256]byte) string {
						result := ""
						for _, p := range params {
							result += fmt.Sprintf("%s ", string(p[:]))
						}
						return result
					}
					fmt.Printf("[processCreate] PID: %d, PPID: %d, TGID: %d, UID: %d, Command: %s, Filename: %s, Argv: %s\n",
						event.PID, event.PPID, event.TGID, event.UID, event.Command, event.Filename, parameterStr(event.Args))
				})
		case "processTerminate":
			startCollector(ctx, "processTerminate", processTerminate.Run,
				func(event processTerminate.ProcessTerminateEvent) {
					fmt.Printf("[processTerminate] PID: %d, UID: %d, Cmdline: %s, Ret: %d\n",
						event.PID, event.UID, event.Cmdline, event.Ret)
				})
		case "vfsOpen":
			startCollector(ctx, "vfsOpen", vfsOpen.Run,
				func(event vfsOpen.VfsOpenFullEvent) {
					// Uncomment and adjust the output as needed.
					// fmt.Printf("[vfsOpen] PID: %d, UID: %d, Full Filepath: %s, Flags: %O (%v)\n",
					// 	event.PID, event.UID, event.FullPath, event.Flags, event.FlagsInterpretation)
				})
		default:
			log.Printf("Unknown collector: %s", c)
		}
	}

	// Wait for a termination signal.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	fmt.Println("Event collectors running. Press Ctrl+C to exit.")
	<-sigCh

	fmt.Println("Termination signal received. Shutting down...")
	cancel()
	time.Sleep(1 * time.Second) // Allow time for graceful shutdown.
}
