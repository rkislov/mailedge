package metrics

import (
	"runtime"
	"time"
)

func processCPUTime() time.Duration {
	return readProcessCPU()
}

func processRSS() uint64 {
	return readProcessRSS()
}

// fallback used when platform file is not selected (should not happen).
func readProcessCPUFallback() time.Duration {
	return 0
}

func readProcessRSSFallback() uint64 {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return ms.Sys
}
