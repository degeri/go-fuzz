// Copyright 2015 Dmitry Vyukov. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build darwin linux freebsd dragonfly

package main

import (
	"log"
	"os"
	"os/exec"
	"syscall"

	"golang.org/x/sys/unix"
)

func lowerProcessPrio() {
	syscall.Setpriority(syscall.PRIO_PROCESS, 0, 19)
}

type Mapping struct {
	f *os.File
}

func createMapping(name string, size int) (*Mapping, []byte) {
	f, err := os.OpenFile(name, os.O_RDWR, 0)
	if err != nil {
		log.Fatalf("failed to open comm file: %v", err)
	}
	mem, err := syscall.Mmap(int(f.Fd()), 0, size, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		log.Fatalf("failed to mmap comm file: %v", err)
	}
	return &Mapping{f}, mem
}

func (m *Mapping) destroy() {
	m.f.Close()
}

func setupCommMapping(cmd *exec.Cmd, comm *Mapping, rOut, wIn *os.File) {
	cmd.ExtraFiles = append(cmd.ExtraFiles, comm.f)
	cmd.ExtraFiles = append(cmd.ExtraFiles, rOut)
	cmd.ExtraFiles = append(cmd.ExtraFiles, wIn)
}

func CPUTime() int64 {
	var t unix.Timespec
	err := unix.ClockGettime(unix.CLOCK_PROCESS_CPUTIME_ID, &t)
	if err != nil {
		return 0
	}
	return t.Nano()
}
