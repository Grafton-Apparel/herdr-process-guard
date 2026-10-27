//go:build linux

package platform

import (
	"os"
	"testing"
)

// BenchmarkLiveProcesses scans the real /proc for the caller's processes, as
// one watchdog poll does: go test -run '^$' -bench LiveProcesses -benchtime 3x ./internal/platform
func BenchmarkLiveProcesses(b *testing.B) {
	s := &Scanner{UID: os.Getuid()}
	for b.Loop() {
		processes, _, err := s.processesNative()
		if err != nil {
			b.Fatal(err)
		}
		b.ReportMetric(float64(len(processes)), "processes")
	}
}
