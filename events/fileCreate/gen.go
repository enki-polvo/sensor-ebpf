// events/fileCreate/gen.go
package fileCreate

import (
	"C"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux fileCreate fileCreate.c
