package watchdog

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestServiceStableBinaryInstallAndNoDetachedWorker(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("systemd install fixture requires Linux")
	}
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

func TestNonLinuxServiceInstallRejectsWithoutMutation(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("non-Linux service contract")
	}
	called := false
	home := t.TempDir()
	s := Service{Home: home, Executable: filepath.Join(home, "missing"), StateDir: filepath.Join(home, "state"), Run: func(...string) error { called = true; return nil }}
	if err := s.Install(); err == nil || !strings.Contains(err.Error(), "requires Linux") {
		t.Fatalf("unsupported install: %v", err)
	}
	if called {
		t.Fatal("unsupported install invoked systemctl")
	}
	if _, err := os.Stat(s.BinaryPath()); !os.IsNotExist(err) {
		t.Fatal("unsupported install wrote binary", err)
	}
	if _, err := os.Stat(s.UnitPath()); !os.IsNotExist(err) {
		t.Fatal("unsupported install wrote unit", err)
	}
	if err := s.Ensure(); err != nil || called {
		t.Fatal("non-Linux ensure should do nothing", err)
	}
}
