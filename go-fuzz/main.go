// Copyright 2015 Dmitry Vyukov. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/pkg/profile"
)

//go:generate go build github.com/dvyukov/go-fuzz/go-fuzz/vendor/github.com/elazarl/go-bindata-assetfs/go-bindata-assetfs
//go:generate ./go-bindata-assetfs assets/...
//go:generate rm go-bindata-assetfs
//go:generate goimports -w bindata_assetfs.go

var (
	flagWorkdir       = flag.String("workdir", "", "dir with persistent work data")
	flagProcs         = flag.Int("procs", runtime.NumCPU(), "parallelism level")
	flagTimeout       = flag.Int("timeout", 10, "test timeout, in seconds")
	flagMinimize      = flag.Duration("minimize", 1*time.Minute, "time limit for input minimization")
	flagCoordinator   = flag.String("coordinator", "", "coordinator mode (value is coordinator address)")
	flagWorker        = flag.String("worker", "", "worker mode (value is coordinator address)")
	flagBin           = flag.String("bin", "", "test binary built with go-fuzz-build")
	flagDumpCover     = flag.Bool("dumpcover", false, "dump coverage profile into workdir")
	flagDup           = flag.Bool("dup", false, "collect duplicate crashers")
	flagTestOutput    = flag.Bool("testoutput", false, "print test binary output to stdout (for debugging only)")
	flagCoverCounters = flag.Bool("covercounters", true, "use coverage hit counters")
	flagSonar         = flag.Bool("sonar", true, "use sonar hints")
	flagV             = flag.Int("v", 0, "verbosity level")
	flagHTTP          = flag.String("http", "", "HTTP server listen address (coordinator mode only)")
	flagTTL           = flag.Duration("ttl", 0, "time to fuzz after initial triage complete")
	flagCPUProfile    = flag.Bool("cpuprofile", false, "enable cpu profiling")
	flagCSV           = flag.Bool("csv", false, "print in CSV form instead of plain text")

	requestShutdown = make(chan struct{}, 1)
	shutdown        uint32
	shutdownC       = make(chan struct{})
	shutdownCleanup []func()
)

func main() {
	flag.Parse()
	var prof interface{ Stop() }
	if *flagCPUProfile {
		prof = profile.Start(profile.CPUProfile, profile.ProfilePath("."))
	}
	if *flagCoordinator != "" && *flagWorker != "" {
		log.Fatalf("both -coordinator and -worker are specified")
	}
	if *flagHTTP != "" && *flagWorker != "" {
		log.Fatalf("both -http and -worker are specified")
	}

	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGINT)
		select {
		case <-c:
		case <-requestShutdown:
		}
		atomic.StoreUint32(&shutdown, 1)
		close(shutdownC)
		log.Printf("shutting down...")
		time.Sleep(2 * time.Second)
		for _, f := range shutdownCleanup {
			f()
		}
		if prof != nil {
			prof.Stop()
		}
		os.Exit(0)
	}()

	runtime.GOMAXPROCS(min(*flagProcs, runtime.NumCPU()))
	debug.SetGCPercent(50) // most memory is in large binary blobs
	lowerProcessPrio()

	*flagWorkdir = expandHomeDir(*flagWorkdir)
	*flagBin = expandHomeDir(*flagBin)

	if *flagCoordinator != "" || *flagWorker == "" {
		if *flagWorkdir == "" {
			log.Fatalf("-workdir is not set")
		}
		if *flagCoordinator == "" {
			*flagCoordinator = "localhost:0"
		}
		ln, err := net.Listen("tcp", *flagCoordinator)
		if err != nil {
			log.Fatalf("failed to listen: %v", err)
		}
		if *flagCoordinator == "localhost:0" && *flagWorker == "" {
			*flagWorker = ln.Addr().String()
		}
		go coordinatorMain(ln)
	}

	if *flagWorker != "" {
		if *flagBin == "" {
			log.Fatalf("-bin is not set")
		}
		go workerMain()
	}

	select {}
}

// expandHomeDir expands the tilde sign and replaces it
// with current users home directory and returns it.
func expandHomeDir(path string) string {
	if len(path) > 2 && path[:2] == "~/" {
		usr, _ := user.Current()
		path = filepath.Join(usr.HomeDir, path[2:])
	}
	return path
}
