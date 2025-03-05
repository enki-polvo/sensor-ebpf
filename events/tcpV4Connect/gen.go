// events/tcpV4Connect/gen.go
package tcpV4Connect

import (
	"C"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux tcpV4Connect tcpV4Connect.c
