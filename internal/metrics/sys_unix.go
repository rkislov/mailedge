//go:build unix

package metrics

import (
	"runtime"
	"syscall"
	"time"
)

func readProcessCPU() time.Duration {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		return 0
	}
	return time.Duration(ru.Utime.Nano()+ru.Stime.Nano()) * time.Nanosecond
}

func readProcessRSS() uint64 {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		return readProcessRSSFallback()
	}
	rss := uint64(ru.Maxrss)
	if runtime.GOOS == "darwin" {
		return rss // bytes on macOS
	}
	return rss * 1024 // kilobytes on Linux
}
