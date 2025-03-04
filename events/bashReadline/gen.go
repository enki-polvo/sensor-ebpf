// events/bashReadline/gen.go
package bashReadline

import (
	"C"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux bashReadline bashReadline.c
