package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux tcxdp src/tcx_traffic.c
