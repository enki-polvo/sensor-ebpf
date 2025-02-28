// events/networkEvent/gen.go
package networkEvent

import (
	"C"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux tcpConnect tcpConnect.c
