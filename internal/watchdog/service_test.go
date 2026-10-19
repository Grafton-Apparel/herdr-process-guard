package watchdog

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestServiceStableBinaryInstallAndNoDetachedWorker(t *testing.T) {
	home := t.TempDir()
	exe := filepath.Join(t.TempDir(), "dev binary")
	_ = os.WriteFile(exe, []byte("binary"), 0700)
	calls := [][]string{}
	s := Service{Home: home, Executable: exe, StateDir: filepath.Join(home, "state"), Run: func(args ...string) error { calls = append(calls, args); return nil }}
	if err := s.Install(); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(s.UnitPath())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "Restart=on-failure") || !strings.Contains(string(body), s.BinaryPath()) || strings.Contains(string(body), exe) || strings.Contains(string(body), "HERDR_SOCKET_PATH") {
		t.Fatalf("unsafe unit %s", body)
	}
	if len(calls) != 1 || strings.Join(calls[0], " ") != "daemon-reload" {
		t.Fatal(calls)
	}
	if err = s.Ensure(); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 || strings.Join(calls[1], " ") != "start --no-block herdr-process-guard.service" {
		t.Fatal(calls)
	}
	if err = os.Remove(s.UnitPath()); err != nil {
		t.Fatal(err)
	}
	if err = s.Ensure(); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 {
		t.Fatal("spawned without installed service")
	}
}
