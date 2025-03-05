// events/tcpV4Accept/gen.go
package tcpV4Accept

import (
	"C"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux tcpV4Accept tcpV4Accept.c
