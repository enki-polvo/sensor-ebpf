package bashReadline

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

const (
	// The path to the ELF binary containing the function to trace.
	binPath = "/bin/bash"
	symbol  = "readline"
)

// BashReadlineEventOriginal mirrors the C structure with a fixed-size byte array.
type BashReadlineEventOriginal struct {
	UID         uint32
	PID         uint32
	Commandline [256]byte
}

// BashReadlineEvent is our final structure with a proper string field.
type BashReadlineEvent struct {
	UID         uint32
	PID         uint32
	Commandline string
}

// Run starts the bash command collector and sends events over the provided channel.
// It closes the channel when exiting.
func Run(ctx context.Context, events chan<- BashReadlineEvent) error {
	// Remove resource limits.
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("failed to remove memlock limit: %w", err)
	}

	// Load pre-compiled BPF objects.
	objs := bashReadlineObjects{}
	if err := loadBashReadlineObjects(&objs, nil); err != nil {
		return fmt.Errorf("loading objects: %w", err)
	}
	defer objs.Close()

	// Open an ELF binary and read its symbols.
	executable, err := link.OpenExecutable(binPath)
	if err != nil {
		return fmt.Errorf("failed to open and load ELF binary: %w", err)
	}

	// Attach the uprobe at the entry point of the symbol.
	upBashReadline, err := executable.Uretprobe(symbol, objs.UprobeBashReadline, nil)
	if err != nil {
		return fmt.Errorf("failed to attach uprobe: %w", err)
	}
	defer upBashReadline.Close()

	// Open a perf event reader from userspace on the PERF_EVENT_ARRAY map described in the BPF program.
	rd, err := perf.NewReader(objs.BashReadlineEventMap, os.Getpagesize())
	if err != nil {
		return fmt.Errorf("failed to open perf event reader: %w", err)
	}
	defer rd.Close()

	// Launch a goroutine to process events.
	go func() {
		defer close(events)
		for {
			select {
			case <-ctx.Done():
				log.Println("Context cancelled, stopping event reader")
				return
			default:
			}

			// Read an event record.
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, perf.ErrClosed) {
					return
				}
				log.Printf("reading from perf event reader: %v", err)
				continue
			}

			// Check if any samples were lost.
			if record.LostSamples > 0 {
				log.Printf("perf event ring buffer full, dropped %d samples", record.LostSamples)
				continue
			}

			// Decode the raw sample into our original event structure.
			var rawEvent BashReadlineEventOriginal
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &rawEvent); err != nil {
				log.Printf("parsing perf event: %v", err)
				continue
			}

			// Clearly cut the commandline string, so we don't print garbage.
			cmdBytes := rawEvent.Commandline[:]
			if i := bytes.IndexByte(cmdBytes, 0); i != -1 {
				cmdBytes = cmdBytes[:i]
			}
			cmdLine := string(cmdBytes)

			// Create our final event structure.
			event := BashReadlineEvent{
				UID:         rawEvent.UID,
				PID:         rawEvent.PID,
				Commandline: cmdLine,
			}

			// Send the event over the channel.
			select {
			case events <- event:
			case <-ctx.Done():
				return
			}
		}
	}()

	// Block until context is cancelled.
	<-ctx.Done()
	return nil
}
