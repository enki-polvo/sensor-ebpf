// events/vfsOpen/gen.go
package vfsOpen

import (
	"C"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux vfsOpen vfsOpen.c
