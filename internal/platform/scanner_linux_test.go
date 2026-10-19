//go:build linux

package platform

import (
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Efeguclu1/herdr-process-guard/internal/model"
)

func procFixture(t *testing.T) *Scanner {
	t.Helper()
	root := t.TempDir()
	writeFixture(t, root, "stat", "cpu 0 0\nbtime 1700000000\n")
	writeFixture(t, root, "sys/kernel/random/boot_id", "fixture-boot\n")
	return &Scanner{UID: os.Getuid(), ProcRoot: root, ClockTicks: 100}
}
func writeFixture(t *testing.T, root, name, value string) {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(value), 0600); err != nil {
		t.Fatal(err)
	}
}
func fixtureProcess(t *testing.T, s *Scanner, pid int) {
	t.Helper()
	base := fmt.Sprint(pid)
	// Fields 4..24: ppid, pgrp, session, ... utime, stime, ... starttime, vsize, rss.
	stat := fmt.Sprintf("%d (worker (a) space) S 7 42 7 0 0 0 0 0 0 0 150 50 0 0 0 0 1 0 1234 4096 2\n", pid)
	writeFixture(t, s.ProcRoot, base+"/stat", stat)
	writeFixture(t, s.ProcRoot, base+"/status", fmt.Sprintf("Name:\tworker\nUid:\t%d\t%d\t%d\t%d\n", s.UID, s.UID, s.UID, s.UID))
	writeFixture(t, s.ProcRoot, base+"/cmdline", "/usr/bin/node\x00server.js\x00")
	writeFixture(t, s.ProcRoot, base+"/task/"+base+"/children", "")
	writeFixture(t, s.ProcRoot, base+"/io", "rchar: 50\nwchar: 60\nread_bytes: 10\nwrite_bytes: 20\n")
	for name, target := range map[string]string{"exe": "/usr/bin/node", "cwd": "/work"} {
		if err := os.Symlink(target, filepath.Join(s.ProcRoot, base, name)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(s.ProcRoot, base, "fd"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"tcp", "tcp6", "udp", "udp6", "unix"} {
		writeFixture(t, s.ProcRoot, base+"/net/"+name, "header\n")
	}
}
func TestLinuxProcSnapshot(t *testing.T) {
	s := procFixture(t)
	fixtureProcess(t, s, 42)
	writeFixture(t, s.ProcRoot, "42/net/tcp", "header\n 0: 0100007F:1F90 0200007F:C350 01 0:0 0:0 0 0 0 12345\n")
	if err := os.Symlink("socket:[12345]", filepath.Join(s.ProcRoot, "42/fd/3")); err != nil {
		t.Fatal(err)
	}
	processes, warnings, err := s.Processes()
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) > 0 {
		t.Fatal(warnings)
	}
	p := processes[42]
	if p.Name != "worker (a) space" || p.Key.BootID != "fixture-boot" || p.Key.StartTicks != 1234 || p.Key.StartUnixMS != 1700000012340 {
		t.Fatalf("identity: %+v", p)
	}
	if p.CPUTimeMillis != 2000 || p.RSSBytes != uint64(2*os.Getpagesize()) || p.IOReadBytes != 10 || p.IOWriteChars != 60 {
		t.Fatalf("counters: %+v", p)
	}
	if !p.TelemetryComplete || !p.SocketsComplete || !p.IOComplete || !p.HasEstablishedConnection() {
		t.Fatalf("completeness/socket: %+v", p)
	}
	if p.Sockets[0].Local != "127.0.0.1:8080" {
		t.Fatalf("socket: %+v", p.Sockets)
	}
	if got := p.Key.String(); got != "42:fixture-boot:1234" {
		t.Fatal(got)
	}
	if got := (model.ProcessKey{PID: 42, StartUnixMS: 9}).String(); got != "42:9" {
		t.Fatal(got)
	}
}
func TestLinuxIncompleteSnapshotFailsClosed(t *testing.T) {
	for _, missing := range []string{"io", "exe", "status", "net/tcp", "fd"} {
		t.Run(missing, func(t *testing.T) {
			s := procFixture(t)
			fixtureProcess(t, s, 42)
			if err := os.RemoveAll(filepath.Join(s.ProcRoot, "42", missing)); err != nil {
				t.Fatal(err)
			}
			ps, warnings, err := s.Processes()
			if err != nil {
				t.Fatal(err)
			}
			if len(warnings) == 0 {
				t.Fatal("missing warning")
			}
			if p, ok := ps[42]; ok && p.TelemetryComplete {
				t.Fatalf("incomplete process accepted: %+v", p)
			}
		})
	}
}
func TestLinuxIgnoresOtherUID(t *testing.T) {
	s := procFixture(t)
	fixtureProcess(t, s, 42)
	writeFixture(t, s.ProcRoot, "42/status", fmt.Sprintf("Uid:\t%d\t%d\t%d\t%d\n", s.UID+1, s.UID+1, s.UID+1, s.UID+1))
	ps, warnings, err := s.Processes()
	if err != nil || len(warnings) != 0 || len(ps) != 0 {
		t.Fatalf("%v %v %v", ps, warnings, err)
	}
}
func TestLinuxPinRefusesFixtures(t *testing.T) {
	s := procFixture(t)
	fixtureProcess(t, s, 42)
	ps, _, _ := s.Processes()
	if pin, err := s.Pin(ps[42]); err == nil {
		pin.Close()
		t.Fatal("fixture must never signal real PID")
	}
}
func TestLinuxPinRejectsChangedIdentityAndTerminatesChild(t *testing.T) {
	cmd := exec.Command("sleep", "60")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	s := NewScanner()
	ps, _, err := s.Processes()
	if err != nil {
		t.Fatal(err)
	}
	p, ok := ps[cmd.Process.Pid]
	if !ok || !p.TelemetryComplete {
		t.Fatalf("child missing/incomplete: %+v", p)
	}
	for _, change := range []func(*model.Process){func(p *model.Process) { p.Key.StartTicks++ },
		func(p *model.Process) { p.Key.PID = os.Getpid() }, func(p *model.Process) { p.UID++ }, func(p *model.Process) { p.Executable += "-changed" }, func(p *model.Process) { p.CommandHash = "changed" }, func(p *model.Process) { p.Key.BootID = "changed" }, func(p *model.Process) { p.Command = "changed" }} {
		bad := p
		change(&bad)
		if pin, err := s.Pin(bad); err == nil {
			pin.Close()
			t.Fatal("accepted changed identity")
		}
	}
	pin, err := s.Pin(p)
	if err != nil {
		t.Fatal(err)
	}
	defer pin.Close()
	if err := pin.Revalidate(); err != nil {
		t.Fatal(err)
	}
	if err := pin.SIGTERM(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "terminated") {
			t.Fatalf("wait: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("child survived")
	}
	if err := pin.Revalidate(); err == nil {
		t.Fatal("revalidated exited child")
	}
	if err := pin.Close(); err != nil {
		t.Fatal(err)
	}
	if err := pin.SIGTERM(); err == nil {
		t.Fatal("signaled closed pin")
	}
}

func TestLinuxRejectsPIDReuseDuringRead(t *testing.T) {
	for _, state := range []string{"S", "Z"} {
		t.Run(state, func(t *testing.T) {
			s := procFixture(t)
			fixtureProcess(t, s, 42)
			path := filepath.Join(s.ProcRoot, "42/stat")
			original, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			original = []byte(strings.Replace(string(original), ") S ", ") "+state+" ", 1))
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := unix.Mkfifo(path, 0600); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				f, err := os.OpenFile(path, os.O_WRONLY, 0)
				if err != nil {
					done <- err
					return
				}
				defer f.Close()
				if err := os.Remove(path); err != nil {
					done <- err
					return
				}
				changed := strings.Replace(string(original), "1234 4096", "9999 4096", 1)
				if err := os.WriteFile(path, []byte(changed), 0600); err != nil {
					done <- err
					return
				}
				_, err = f.Write(original)
				done <- err
			}()
			ps, warnings, err := s.Processes()
			if err != nil {
				t.Fatal(err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if s.GraphComplete || ps[42].TelemetryComplete || ps[42].Key.PID != 42 || len(warnings) == 0 {
				t.Fatalf("recycled PID accepted or graph stub lost: %v %v", ps, warnings)
			}
		})
	}
}
func TestLinuxSocketGapsFailClosed(t *testing.T) {
	for _, row := range []string{" 0: 0100007F:1F90 0200007F:C350 ZZ 0:0 0:0 0 0 0 12345\n", " 0: invalid 0200007F:C350 01 0:0 0:0 0 0 0 12345\n", ""} {
		s := procFixture(t)
		fixtureProcess(t, s, 42)
		writeFixture(t, s.ProcRoot, "42/net/tcp", "header\n"+row)
		if err := os.Symlink("socket:[12345]", filepath.Join(s.ProcRoot, "42/fd/3")); err != nil {
			t.Fatal(err)
		}
		ps, warnings, err := s.Processes()
		if err != nil {
			t.Fatal(err)
		}
		if len(warnings) == 0 || ps[42].SocketsComplete || ps[42].TelemetryComplete {
			t.Fatalf("socket gap accepted: %q %+v %v", row, ps[42], warnings)
		}
	}
}
func TestLinuxPermissionGapAndDisappearance(t *testing.T) {
	s := procFixture(t)
	fixtureProcess(t, s, 42)
	if os.Getuid() != 0 {
		if err := os.Chmod(filepath.Join(s.ProcRoot, "42/io"), 0000); err != nil {
			t.Fatal(err)
		}
		ps, warnings, err := s.Processes()
		if err != nil {
			t.Fatal(err)
		}
		if len(warnings) == 0 || ps[42].IOComplete || ps[42].TelemetryComplete {
			t.Fatal("permission gap accepted")
		}
	}
	if err := os.Remove(filepath.Join(s.ProcRoot, "42/stat")); err != nil {
		t.Fatal(err)
	}
	ps, warnings, err := s.Processes()
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != 0 || len(warnings) == 0 {
		t.Fatalf("disappearance: %v %v", ps, warnings)
	}
}
func TestLinuxBoundsProcReads(t *testing.T) {
	s := procFixture(t)
	fixtureProcess(t, s, 42)
	writeFixture(t, s.ProcRoot, "42/cmdline", strings.Repeat("x", maxProcFile+1))
	ps, warnings, err := s.Processes()
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) == 0 || ps[42].TelemetryComplete {
		t.Fatal("oversized command accepted")
	}
}

func TestLinuxScannerCanReadItsOwnFDs(t *testing.T) {
	s := NewScanner()
	ps, warnings, err := s.Processes()
	if err != nil {
		t.Fatal(err)
	}
	if !ps[os.Getpid()].SocketsComplete {
		t.Fatalf("self observation incomplete: %+v warnings=%v", ps[os.Getpid()], warnings)
	}
}

func TestLinuxPinRejectsExecAfterPin(t *testing.T) {
	cmd := exec.Command("sh", "-c", "read line; exec sleep 60")
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { input.Close(); cmd.Process.Kill(); cmd.Wait() }()
	s := NewScanner()
	ps, _, err := s.Processes()
	if err != nil {
		t.Fatal(err)
	}
	original := ps[cmd.Process.Pid]
	pin, err := s.Pin(original)
	if err != nil {
		t.Fatal(err)
	}
	defer pin.Close()
	if _, err := input.Write([]byte("go\n")); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		executable, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", cmd.Process.Pid))
		if err != nil {
			t.Fatal(err)
		}
		if executable != original.Executable {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("child did not exec")
		}
		time.Sleep(time.Millisecond)
	}
	if err := pin.Revalidate(); err == nil {
		t.Fatal("accepted exec after pin")
	}
	if err := pin.SIGTERM(); err == nil {
		t.Fatal("signaled changed executable")
	}
}

func TestLinuxGraphCompletenessIndependentOfTargetMetadata(t *testing.T) {
	for _, missing := range []string{"io", "exe", "net/tcp", "status", "stat"} {
		t.Run(missing, func(t *testing.T) {
			s := procFixture(t)
			fixtureProcess(t, s, 42)
			if err := os.RemoveAll(filepath.Join(s.ProcRoot, "42", missing)); err != nil {
				t.Fatal(err)
			}
			ps, _, err := s.Processes()
			if err != nil {
				t.Fatal(err)
			}
			wantGraph := missing != "status" && missing != "stat"
			if s.GraphComplete != wantGraph {
				t.Fatalf("graph=%v want=%v", s.GraphComplete, wantGraph)
			}
			if missing == "status" && (ps[42].Key.PID != 42 || ps[42].PPID != 7 || ps[42].UID != -1 || ps[42].TelemetryComplete) {
				t.Fatalf("missing graph stub: %+v", ps[42])
			}
		})
	}
}
func TestLinuxZombieKeepsGraphWithoutNormalMetadataWarnings(t *testing.T) {
	s := procFixture(t)
	fixtureProcess(t, s, 42)
	path := filepath.Join(s.ProcRoot, "42/stat")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	writeFixture(t, s.ProcRoot, "42/stat", strings.Replace(string(b), ") S ", ") Z ", 1))
	for _, name := range []string{"cmdline", "exe", "io", "fd", "cwd"} {
		if err := os.RemoveAll(filepath.Join(s.ProcRoot, "42", name)); err != nil {
			t.Fatal(err)
		}
	}
	ps, warnings, err := s.Processes()
	if err != nil {
		t.Fatal(err)
	}
	p := ps[42]
	if !s.GraphComplete || len(warnings) != 0 || p.Key.PID != 42 || p.PPID != 7 || p.State != "Z" || p.TelemetryComplete {
		t.Fatalf("zombie: graph=%v process=%+v warnings=%v", s.GraphComplete, p, warnings)
	}
}

func TestLinuxMixedCredentialsPreserveGraphButBlockSignal(t *testing.T) {
	s := procFixture(t)
	fixtureProcess(t, s, 42)
	writeFixture(t, s.ProcRoot, "42/status", fmt.Sprintf("Uid:\t%d\t%d\t0\t%d\n", s.UID, s.UID, s.UID))
	ps, warnings, err := s.Processes()
	if err != nil {
		t.Fatal(err)
	}
	if !s.GraphComplete || ps[42].UID != s.UID || ps[42].TelemetryComplete || len(warnings) == 0 {
		t.Fatalf("mixed creds: graph=%v %+v %v", s.GraphComplete, ps[42], warnings)
	}
}

func TestLinuxKernelChildrenIncludeForeignUIDAndThreadForks(t *testing.T) {
	s := procFixture(t)
	fixtureProcess(t, s, 42)
	fixtureProcess(t, s, 99)
	writeFixture(t, s.ProcRoot, "99/status", fmt.Sprintf("Uid:\t%d\t%d\t%d\t%d\n", s.UID+1, s.UID+1, s.UID+1, s.UID+1))
	writeFixture(t, s.ProcRoot, "42/task/43/children", "99 ")
	ps, warnings, err := s.Processes()
	if err != nil {
		t.Fatal(err)
	}
	p := ps[42]
	if !s.GraphComplete || !p.ChildrenComplete || !p.TelemetryComplete || len(p.Children) != 1 || p.Children[0] != 99 || len(warnings) != 0 {
		t.Fatalf("missing foreign child: %+v %v", p, warnings)
	}
	if _, ok := ps[99]; ok {
		t.Fatal("foreign process metadata included")
	}
}
func TestLinuxChildrenGapBlocksOnlyAffectedTarget(t *testing.T) {
	s := procFixture(t)
	fixtureProcess(t, s, 42)
	if err := os.Remove(filepath.Join(s.ProcRoot, "42/task/42/children")); err != nil {
		t.Fatal(err)
	}
	ps, warnings, err := s.Processes()
	if err != nil {
		t.Fatal(err)
	}
	if !s.GraphComplete || ps[42].ChildrenComplete || ps[42].TelemetryComplete || len(warnings) == 0 {
		t.Fatalf("children gap accepted: graph=%v %+v %v", s.GraphComplete, ps[42], warnings)
	}
}
