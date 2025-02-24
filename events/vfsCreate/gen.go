package vfsCreate

import (
	"C"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux vfsCreate vfsCreate.c
