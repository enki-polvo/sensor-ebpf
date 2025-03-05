// events/tcpAccept/gen.go
package tcpAccept

import (
	"C"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux tcpAccept tcpAccept.c
