//go:build linux

package watchdog

import (
	"bufio"
	"github.com/Efeguclu1/herdr-process-guard/internal/model"
	"github.com/Efeguclu1/herdr-process-guard/internal/platform"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Only this test-owned sleep may receive a signal. Session/process enumeration is a
// controlled fixture; native procfs identities and pidfd signaling remain real.
func TestDisposableAttributedOrphanPIDFDEndToEnd(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "codex")
	data, err := os.ReadFile("/bin/sh")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(bin, data, 0700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "-c", "sleep 300 & echo $!; read -r line || :")
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = in.Close(); _ = cmd.Wait() }()
	line, err := bufio.NewReader(out).ReadString(10)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil {
		t.Fatal(err)
	}
	scanner := platform.NewScanner()
	read := func() model.Process {
		t.Helper()
		ps, _, err := scanner.Processes()
		if err != nil {
			t.Fatal(err)
		}
		p, ok := ps[pid]
		if !ok {
			t.Fatal("disposable child missing")
		}
		return p
	}
	p := read()
	if !telemetry(p) {
		t.Fatalf("test child telemetry incomplete: %+v", p.Key)
	}
	cleanupPin, err := scanner.Pin(p)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanupPin.Close()
	defer func() { _ = cleanupPin.SIGTERM() }()
	st := NewState()
	now := time.Unix(10000, 0)
	agent := proc(cmd.Process.Pid, 10, "codex")
	agent.Key = model.ProcessKey{PID: cmd.Process.Pid, BootID: p.Key.BootID, StartTicks: 999}
	shell := proc(10, 1, "bash")
	shell.Key.BootID = p.Key.BootID
	agent.Children = []int{pid}
	shell.Children = []int{agent.Key.PID}
	live := Snapshot{Complete: true, GraphComplete: true, Processes: map[int]model.Process{10: shell, agent.Key.PID: agent, pid: p}, Sessions: []Session{{Socket: "/disposable-fixture", Panes: []Pane{{ID: "fixture", Shell: shell.Key, Agents: []model.ProcessKey{agent.Key}}}}}}
	Observe(&st, live, now, Defaults())
	if len(st.Records) != 1 {
		t.Fatal("helper not attributed")
	}
	_ = in.Close()
	if err = cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		p = read()
		if p.PPID != cmd.Process.Pid {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("child not orphaned")
		}
		time.Sleep(10 * time.Millisecond)
	}
	orphan := Snapshot{Complete: true, GraphComplete: true, Processes: map[int]model.Process{pid: p}}
	for i := 1; i <= 63; i++ {
		Observe(&st, orphan, now.Add(time.Duration(i)*Defaults().Poll()), Defaults())
	}
	now = now.Add(64 * Defaults().Poll())
	cfg := Defaults()
	cfg.Cleanup = true
	repo := Repository{Directory: t.TempDir()}
	if err = repo.Save(st); err != nil {
		t.Fatal(err)
	}
	signals := 0
	r := Runner{Config: cfg, Repo: repo, Now: func() time.Time { return now }, Source: func() (Snapshot, error) {
		ps, _, err := scanner.Processes()
		if err != nil {
			return Snapshot{}, err
		}
		psChild := map[int]model.Process{}
		if p, ok := ps[pid]; ok {
			psChild[pid] = p
		}
		return Snapshot{Complete: true, GraphComplete: true, Processes: psChild}, nil
	}, Pin: func(p model.Process) (Pin, error) { signals++; return scanner.Pin(p) }, Sleep: func(time.Duration) { time.Sleep(100 * time.Millisecond) }}
	if err = r.Once(&st); err != nil {
		t.Fatal(err)
	}
	if signals != 1 {
		t.Fatalf("native pidfd attempt count %d", signals)
	}
	ps, _, err := scanner.Processes()
	if err != nil {
		t.Fatal(err)
	}
	if p, ok := ps[pid]; ok && !strings.Contains(p.State, "Z") {
		t.Fatalf("disposable child survived SIGTERM: %v", p.Key)
	}
	saved, err := repo.Load()
	if err != nil || !saved.Records[p.Key.String()].Attempted {
		t.Fatal("attempt not persisted", err)
	}
	_, _ = io.Copy(io.Discard, out)
}
