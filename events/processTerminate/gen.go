// events/processTerminate/gen.go
package processTerminate

import (
	"C"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux processTerminate processTerminate.c
