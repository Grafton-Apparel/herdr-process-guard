package watchdog

import (
	"bufio"
	"encoding/json"
	"github.com/Efeguclu1/herdr-process-guard/internal/model"
	"github.com/Efeguclu1/herdr-process-guard/internal/store"
	"net"
	"path/filepath"
	"testing"
)

func socketFixture(t *testing.T, malformed bool) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "herdr.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				var r map[string]any
				_ = json.NewDecoder(bufio.NewReader(c)).Decode(&r)
				var result any
				switch r["method"] {
				case "session.snapshot":
					snap := map[string]any{"version": "0.9.5", "protocol": 1, "panes": []any{map[string]any{"pane_id": "p", "agent": "codex", "agent_status": "idle"}}, "agents": []any{}}
					if malformed {
						snap = map[string]any{}
					}
					result = map[string]any{"type": "session_snapshot", "snapshot": snap}
				case "pane.process_info":
					result = map[string]any{"type": "pane_process_info", "process_info": map[string]any{"pane_id": "p", "shell_pid": 10, "foreground_processes": []any{map[string]any{"pid": 20, "name": "codex"}}}}
				}
				_ = json.NewEncoder(c).Encode(map[string]any{"id": r["id"], "result": result})
			}()
		}
	}()
	return path
}
func TestCollectorAllSessionsSharedIntentionalAndRPC(t *testing.T) {
	t.Setenv("HERDR_PLUGIN_STATE_DIR", t.TempDir())
	a := socketFixture(t, false)
	b := socketFixture(t, false)
	fixture := liveFixture()
	dir, _ := store.SessionDirectory(b)
	_, err := store.New(dir).Update(func(s *model.PersistedState) error {
		s.Approvals[fixture.Processes[30].Key.String()] = model.Approval{Root: fixture.Processes[30].Key, Members: []model.ProcessKey{fixture.Processes[30].Key}}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	c := Collector{Paths: func() ([]string, []string, error) { return []string{a, b}, nil, nil }, Processes: func() (map[int]model.Process, []string, bool, error) { return fixture.Processes, nil, true, nil }}
	s, err := c.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if !s.Complete || len(s.Sessions) != 2 || len(s.Sessions[0].Panes[0].Agents) != 1 || !s.Intentional[fixture.Processes[30].Key.String()] {
		t.Fatalf("bad snapshot: %+v", s)
	}
	c.Paths = func() ([]string, []string, error) { return []string{a, "/missing/socket"}, nil, nil }
	s, err = c.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if s.Complete {
		t.Fatal("unreachable socket accepted")
	}
}
func TestCollectorMalformedSnapshotAndUnknownShellBlock(t *testing.T) {
	path := socketFixture(t, true)
	c := Collector{Paths: func() ([]string, []string, error) { return []string{path}, nil, nil }, Processes: func() (map[int]model.Process, []string, bool, error) { return map[int]model.Process{}, nil, true, nil }}
	s, err := c.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if s.Complete {
		t.Fatal("malformed snapshot accepted")
	}
	path = socketFixture(t, false)
	s, err = c.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if s.Complete {
		t.Fatal("missing shell accepted")
	}
}
