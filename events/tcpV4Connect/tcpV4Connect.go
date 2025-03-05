// events/tcpV4Connect/tcpV4Connect.go
package tcpV4Connect

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

// TcpV4ConnectEventRaw mirrors the C structure's binary layout (24 bytes).
type TcpV4ConnectEventRaw struct {
	PID      uint32
	UID      uint32
	SaFamily uint32
	Saddr    [4]byte // Source IP in network byte order.
	Daddr    [4]byte // Destination IP in network byte order.
	Sport    uint16
	Dport    uint16
}

// TcpV4ConnectEvent is the friendly version with string IP addresses.
type TcpV4ConnectEvent struct {
	PID   uint32
	UID   uint32
	Saddr string // e.g. "192.168.1.100"
	Daddr string // e.g. "93.184.216.34"
	Sport uint16
	Dport uint16
}

// convertEvent converts the raw event into a human-friendly event.
func convertEvent(raw TcpV4ConnectEventRaw) TcpV4ConnectEvent {
	return TcpV4ConnectEvent{
		PID:   raw.PID,
		UID:   raw.UID,
		Saddr: net.IP(raw.Saddr[:]).String(),
		Daddr: net.IP(raw.Daddr[:]).String(),
		Sport: raw.Sport,
		Dport: raw.Dport,
	}
}

// Run starts the TCP IPv4 connect event collector.
func Run(ctx context.Context, events chan<- TcpV4ConnectEvent) error {
	// Remove resource limits.
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("failed to remove memlock resource limit: %w", err)
	}

	// Load pre-compiled BPF objects.
	objs := tcpV4ConnectObjects{}
	if err := loadTcpV4ConnectObjects(&objs, nil); err != nil {
		return fmt.Errorf("failed to load BPF objects: %w", err)
	}
	defer objs.Close()

	// Attach the entry probe.
	kpEntry, err := link.Kprobe("tcp_v4_connect", objs.TcpV4ConnectEntry, nil)
	if err != nil {
		return fmt.Errorf("failed to attach entry kprobe: %w", err)
	}
	defer kpEntry.Close()

	// Attach the return (kretprobe) probe.
	kpRet, err := link.Kretprobe("tcp_v4_connect", objs.TcpV4ConnectRet, nil)
	if err != nil {
		return fmt.Errorf("failed to attach return kretprobe: %w", err)
	}
	defer kpRet.Close()

	// Open a ring buffer reader on the map.
	rd, err := ringbuf.NewReader(objs.TcpV4ConnectEventMap)
	if err != nil {
		return fmt.Errorf("failed to open ring buffer reader: %w", err)
	}
	defer rd.Close()

	log.Printf("Listening for TCP IPv4 connect events (kprobe/tcp_v4_connect, kretprobe/tcp_v4_connect)")
	defer close(events)

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			// Read the next event from the ring buffer.
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					log.Println("ring buffer closed, exiting")
					return nil
				}
				log.Printf("error reading from ring buffer: %v", err)
				continue
			}

			var rawEvent TcpV4ConnectEventRaw
			// Parse the raw binary data into our raw event structure.
			err = binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &rawEvent)
			if err != nil {
				log.Printf("error parsing event: %v", err)
				continue
			}

			// Convert the raw event to a human-friendly event.
			event := convertEvent(rawEvent)

			// Send the event over the channel.
			select {
			case events <- event:
			case <-ctx.Done():
				return nil
			}
		}
	}
}
