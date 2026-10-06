//go:build !unix

package metrics

import "time"

func readProcessCPU() time.Duration {
	return readProcessCPUFallback()
}

func readProcessRSS() uint64 {
	return readProcessRSSFallback()
}
