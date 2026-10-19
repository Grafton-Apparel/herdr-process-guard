//go:build linux

package platform

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestLinuxPIDNamespaceMustMatchProcMount(t *testing.T) {
	for _, status := range []string{"", "NSpid:\t42 42\n", "NSpid:\t43\n"} {
		if samePIDNamespace([]byte(status), 42) {
			t.Fatalf("ambiguous PID namespace accepted: %q", status)
		}
	}
	if !samePIDNamespace([]byte("Name:\tfixture\nNSpid:\t42\n"), 42) {
		t.Fatal("matching proc PID namespace rejected")
	}
}

func TestLinuxReapedPIDIsConfirmedGone(t *testing.T) {
	if !procUsesCallerPIDNamespace() {
		t.Skip("procfs is not in the caller PID namespace")
	}
	fd, err := unix.PidfdOpen(os.Getpid(), 0)
	if err != nil {
		t.Skipf("pidfds unavailable: %v", err)
	}
	_ = unix.Close(fd)
	child := exec.Command("true")
	if err = child.Run(); err != nil {
		t.Fatal(err)
	}
	s := NewScanner()
	boot, started, ticks, err := s.procInfo()
	if err != nil {
		t.Fatal(err)
	}
	_, skip, err := s.readProcess(child.Process.Pid, boot, started, ticks)
	if err != nil || !skip {
		t.Fatalf("reaped process remains an unknown live graph gap: skip=%v err=%v", skip, err)
	}
	fixture := procFixture(t)
	_, _, err = fixture.readProcess(child.Process.Pid, "fixture-boot", 0, 100)
	if !errors.Is(err, errGraphIncomplete) {
		t.Fatalf("fixture PID must not consult native pidfds: %v", err)
	}
}

func TestLinuxExitConfirmationRequiresAbsentDirectoryAndKernelESRCH(t *testing.T) {
	for _, kind := range []string{"gone", "present", "live-hidden", "unsupported", "permission", "resource", "reused"} {
		t.Run(kind, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "42")
			if kind == "present" {
				if err := os.Mkdir(dir, 0700); err != nil {
					t.Fatal(err)
				}
			}
			calls := 0
			got := confirmedExitedPID(dir, 42, func(pid, flags int) (int, error) {
				calls++
				if pid != 42 || flags != 0 {
					t.Fatal("unexpected pidfd parameters")
				}
				switch kind {
				case "live-hidden":
					return unix.Open("/dev/null", unix.O_RDONLY, 0)
				case "unsupported":
					return -1, unix.ENOSYS
				case "permission":
					return -1, unix.EPERM
				case "resource":
					return -1, unix.EMFILE
				case "reused":
					if err := os.Mkdir(dir, 0700); err != nil {
						t.Fatal(err)
					}
				}
				return -1, unix.ESRCH
			})
			if got != (kind == "gone") || kind == "present" && calls != 0 {
				t.Fatalf("confirmation=%v verifier calls=%d", got, calls)
			}
		})
	}
}
