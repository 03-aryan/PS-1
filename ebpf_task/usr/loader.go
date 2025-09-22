// usr/loader.go
package main

import (
    "fmt"
    "log"
    "os"

    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/link"
)

func main() {
    coll, err := ebpf.LoadCollection("drop_port.o")
    if err != nil {
        log.Fatalf("failed to load eBPF object: %v", err)
    }
    defer coll.Close()

    prog := coll.Programs["block_port"]
    if prog == nil {
        log.Fatal("program not found")
    }

    cgroupPath := "/sys/fs/cgroup"
    if _, err := os.Stat(cgroupPath); os.IsNotExist(err) {
        log.Fatalf("cgroup path does not exist: %s", cgroupPath)
    }

    lnk, err := link.AttachCgroup(link.CgroupOptions{
        Path:    cgroupPath,
        Attach:  ebpf.AttachCGroupInet4Connect,
        Program: prog,
    })
    if err != nil {
        log.Fatalf("failed to attach program: %v", err)
    }
    defer lnk.Close()

    fmt.Println("eBPF program loaded and attached")

    key := uint32(0)
    port := uint16(4040)
    if err := coll.Maps["blocked_port"].Put(&key, &port); err != nil {
        log.Fatalf("failed to set port: %v", err)
    }
    fmt.Printf("Blocking TCP port: %d\n", port)

        for {}
}
