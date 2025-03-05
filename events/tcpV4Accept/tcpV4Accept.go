// events/tcpV4Accept/tcpV4Accept.go
package tcpV4Accept

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// TcpV4AcceptEventRaw matches the kernel event structure exactly.
type TcpV4AcceptEventRaw struct {
	PID        uint32
	UID        uint32
	SaFamily   uint32
	LocalAddr  [4]byte
	RemoteAddr [4]byte
	LocalPort  uint16
	RemotePort uint16
}

// TcpV4AcceptEvent is the parsed event structure.
type TcpV4AcceptEvent struct {
	PID        uint32
	UID        uint32
	LocalIP    string
	RemoteIP   string
	LocalPort  uint16
	RemotePort uint16
}

// convertEvent converts the raw event to a parsed event.
func convertEvent(raw TcpV4AcceptEventRaw) TcpV4AcceptEvent {
	return TcpV4AcceptEvent{
		UID:        raw.UID,
		LocalIP:    net.IP(raw.LocalAddr[:]).String(),
		RemoteIP:   net.IP(raw.RemoteAddr[:]).String(),
		LocalPort:  raw.LocalPort,
		RemotePort: raw.RemotePort,
	}
}

// Run starts the TCP IPv4 accept event collector.
func Run(ctx context.Context, events chan<- TcpV4AcceptEvent) error {
	// Remove resource limits.
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("failed to set rlimit: %w", err)
	}

	// Load pre-compiled BPF objects.
	objs := tcpV4AcceptObjects{}
	if err := loadTcpV4AcceptObjects(&objs, nil); err != nil {
		return fmt.Errorf("failed to load BPF objects: %w", err)
	}
	defer objs.Close()

	// Attach the entry probe.
	kpAcceptEntry, err := link.Kprobe("inet_csk_accept", objs.InetCskAcceptEntry, nil)
	if err != nil {
		return fmt.Errorf("failed to attach kprobe: %w", err)
	}
	defer kpAcceptEntry.Close()

	// Attach the exit probe as a kretprobe.
	kpAcceptExit, err := link.Kretprobe("inet_csk_accept", objs.InetCskAcceptRet, nil)
	if err != nil {
		return fmt.Errorf("failed to attach kretprobe: %w", err)
	}
	defer kpAcceptExit.Close()

	rd, err := ringbuf.NewReader(objs.TcpV4AcceptEventMap)
	if err != nil {
		return fmt.Errorf("failed to open ring buffer: %w", err)
	}
	defer rd.Close()

	log.Println("Listening for TCP v4 accept events (kprobe/inet_csk_accept, kretprobe/inet_csk_accept).")
	defer close(events)

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					log.Println("ring buffer closed, exiting")
					return nil
				}
				log.Printf("error reading from ring buffer: %v", err)
				continue
			}

			var rawEvent TcpV4AcceptEventRaw
			err = binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &rawEvent)
			if err != nil {
				log.Printf("error parsing event: %v", err)
				continue
			}

			event := convertEvent(rawEvent)
			select {
			case events <- event:
			case <-ctx.Done():
				return nil
			}
		}
	}
}
