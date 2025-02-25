// events/processCreate/gen.go
package processCreate

import (
	"C"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux processCreate processCreate.c
