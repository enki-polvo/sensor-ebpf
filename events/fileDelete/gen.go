// events/fileDelete/gen.go
package fileDelete

import (
	"C"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux fileDelete fileDelete.c
