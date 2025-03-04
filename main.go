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
	"sensor-ebpf/events/bashReadline"
	"sensor-ebpf/events/fileCreate"
	"sensor-ebpf/events/fileDelete"
	"sensor-ebpf/events/processCreate"
	"sensor-ebpf/events/processTerminate"
	"sensor-ebpf/events/tcpV4Accept"
	"sensor-ebpf/events/tcpV4Connect"
	"sensor-ebpf/events/vfsOpen"
	"sensor-ebpf/utility"
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
					huh.NewOption("bashReadline", "bashReadline"),
					huh.NewOption("fileCreate", "fileCreate"),
					huh.NewOption("fileDelete", "fileDelete"),
					huh.NewOption("processCreate", "processCreate"),
					huh.NewOption("processTerminate", "processTerminate"),
					huh.NewOption("tcpV4Accept", "tcpV4Accept"),
					huh.NewOption("tcpV4Connect", "tcpV4Connect"),
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
		case "bashReadline":
			startCollector(ctx, "bashReadline", bashReadline.Run,
				func(event bashReadline.BashReadlineEvent) {
					username, _ := utility.GetUsername(event.UID)
					fmt.Printf("[bashCommandline] PID: %d, UID: %d(%s), Bash Commandline: %s\n", event.PID, event.UID, username, event.Commandline)
				})
		case "fileCreate":
			startCollector(ctx, "fileCreate", fileCreate.Run,
				func(event fileCreate.FileCreateEvent) {
					filepath := string(event.Filepath[:])
					username, _ := utility.GetUsername(event.UID)
					fmt.Printf("[fileCreate] PID: %d, UID: %d(%s), Filepath: %s, Flags: %d, Mode: %d\n",
						event.PID, event.UID, username, filepath, event.Flags, event.Mode)
				})
		case "fileDelete":
			startCollector(ctx, "fileDelete", fileDelete.Run,
				func(event fileDelete.FileDeleteEvent) {
					username, _ := utility.GetUsername(event.UID)
					fmt.Printf("[fileDelete] PID: %d, UID: %d(%s), Filepath: %s, Flag: %d\n",
						event.PID, event.UID, username, event.Filepath, event.Flag)
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
					username, _ := utility.GetUsername(event.UID)

					fmt.Printf("[processCreate] PID: %d, PPID: %d, TGID: %d, UID: %d(%s), Command: %s, Filename: %s, Argv: %s\n",
						event.PID, event.PPID, event.TGID, event.UID, username, event.Command, event.Filename, parameterStr(event.Args))
				})
		case "processTerminate":
			startCollector(ctx, "processTerminate", processTerminate.Run,
				func(event processTerminate.ProcessTerminateEvent) {
					username, _ := utility.GetUsername(event.UID)
					fmt.Printf("[processTerminate] PID: %d, UID: %d(%s), Cmdline: %s, Ret: %d\n",
						event.PID, event.UID, username, event.Cmdline, event.Ret)
				})
		case "tcpV4Accept":
			startCollector(ctx, "tcpV4Accept", tcpV4Accept.Run,
				func(event tcpV4Accept.TcpV4AcceptEvent) {
					fmt.Printf("[tcpV4Accept] PID: %d, UID: %d, LocalIP: %s, RemoteIP: %s, LocalPort: %d, RemotePort: %d\n",
						event.PID, event.UID, event.LocalIP, event.RemoteIP, event.LocalPort, event.RemotePort)
				})
		case "tcpV4Connect":
			startCollector(ctx, "tcpV4Connect", tcpV4Connect.Run,
				func(event tcpV4Connect.TcpV4ConnectEvent) {
					username, _ := utility.GetUsername(event.UID)
					fmt.Printf("[tcpV4Connect] PID: %d, UID: %d(%s), Saddr: %s, Daddr: %s, Sport: %d, Dport: %d\n",
						event.PID, event.UID, username, event.Saddr, event.Daddr, event.Sport, event.Dport)
				})
		case "vfsOpen":
			startCollector(ctx, "vfsOpen", vfsOpen.Run,
				func(event vfsOpen.VfsOpenFullEvent) {
					// Uncomment and adjust the output as needed.
					username, _ := utility.GetUsername(event.UID)
					fmt.Printf("[vfsOpen] PID: %d, UID: %d(%s), Full Filepath: %s, Flags: %O (%v)\n",
						event.PID, event.UID, username, event.FullPath, event.Flags, event.FlagsInterpretation)
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
