package watchdog

import (
	"context"
	"fmt"
	"github.com/Efeguclu1/herdr-process-guard/internal/herdr"
	"github.com/Efeguclu1/herdr-process-guard/internal/model"
	"github.com/Efeguclu1/herdr-process-guard/internal/store"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type Collector struct {
	Paths        func() ([]string, []string, error)
	Processes    func() (map[int]model.Process, []string, bool, error)
	KnownSockets func() ([]string, error)
}

func (c *Collector) Snapshot() (Snapshot, error) {
	s := Snapshot{Complete: true, Intentional: map[string]bool{}}
	paths, saved, err := c.Paths()
	if err != nil {
		return s, err
	}
	s.Processes, s.Warnings, s.GraphComplete, err = c.Processes()
	if err != nil {
		return s, err
	}
	for _, name := range saved {
		s.Warnings = append(s.Warnings, "Saved/stopped session (no socket): "+SafeText(filepath.Base(name)))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var mu sync.Mutex
	var wg sync.WaitGroup
	jobs := make(chan string)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range jobs {
				ss, warnings, err := collectSession(ctx, path, s.Processes)
				mu.Lock()
				if err != nil {
					s.Complete = false
					s.Warnings = append(s.Warnings, SafeText(path)+": "+SafeText(err.Error()))
				} else {
					s.Sessions = append(s.Sessions, ss)
					s.Warnings = append(s.Warnings, warnings...)
				}
				mu.Unlock()
			}
		}()
	}
	timedOut := false
	for _, path := range paths {
		select {
		case jobs <- path:
		case <-ctx.Done():
			timedOut = true
		}
	}
	close(jobs)
	wg.Wait()
	if timedOut || ctx.Err() != nil {
		s.Complete = false
		s.Warnings = append(s.Warnings, "session snapshot deadline exceeded")
	}
	sort.Slice(s.Sessions, func(i, j int) bool { return s.Sessions[i].Socket < s.Sessions[j].Socket })
	if c.KnownSockets != nil {
		known, err := c.KnownSockets()
		if err != nil {
			return s, err
		}
		paths = append(paths, known...)
	}
	seen := map[string]bool{}
	for _, path := range paths {
		if seen[path] {
			continue
		}
		seen[path] = true
		dir, err := store.SessionDirectory(path)
		if err != nil {
			return s, err
		}
		state, err := store.New(dir).Load()
		if err != nil {
			return s, err
		}
		for _, approval := range state.Approvals {
			if alive(s, approval.Root) {
				s.Intentional[approval.Root.String()] = true
			}
			for _, member := range approval.Members {
				if alive(s, member) {
					s.Intentional[member.String()] = true
				}
			}
		}
	}
	return s, nil
}
func collectSession(ctx context.Context, path string, processes map[int]model.Process) (Session, []string, error) {
	ss := Session{Socket: path}
	client := &herdr.Client{SocketPath: path, Context: ctx, Timeout: 2 * time.Second}
	snapshot, err := client.SessionSnapshot()
	if err != nil {
		return ss, nil, err
	}
	if snapshot.Version == "" || snapshot.Protocol <= 0 || snapshot.Panes == nil || len(snapshot.Panes) > 512 {
		return ss, nil, fmt.Errorf("incomplete or oversized session snapshot")
	}
	ids := map[string]bool{}
	for _, pane := range snapshot.Panes {
		if ctx.Err() != nil {
			return ss, nil, ctx.Err()
		}
		if pane.PaneID == "" || ids[pane.PaneID] {
			return ss, nil, fmt.Errorf("missing or duplicate pane identity")
		}
		ids[pane.PaneID] = true
		info, err := client.PaneProcessInfo(pane.PaneID)
		if err != nil {
			return ss, nil, err
		}
		if info.PaneID != pane.PaneID || info.ShellPID == nil {
			return ss, nil, fmt.Errorf("pane shell information missing")
		}
		shell, ok := processes[*info.ShellPID]
		if !ok || shell.UID < 0 || strings.Contains(shell.State, "Z") {
			return ss, nil, fmt.Errorf("pane shell absent from process snapshot")
		}
		p := Pane{ID: pane.PaneID, Shell: shell.Key, Status: pane.AgentStatus}
		agentName := pane.Agent
		if agentName == "" {
			agentName = pane.DisplayAgent
		}
		for _, a := range snapshot.Agents {
			if a.PaneID == p.ID {
				if a.Agent != "" {
					agentName = a.Agent
				}
				p.Status = a.AgentStatus
			}
		}
		// Herdr agent metadata plus actual ancestry and exact executable name are required.
		p.IsAgent = agentName != ""
		if agentName != "" {
			for _, process := range processes {
				if agentExecutable(process) && ancestor(Snapshot{Processes: processes}, process.Key.PID, shell.Key.PID) {
					p.Agents = append(p.Agents, process.Key)
				}
			}
		}
		ss.Panes = append(ss.Panes, p)
	}
	return ss, nil, nil
}
func agentExecutable(p model.Process) bool {
	switch strings.ToLower(filepath.Base(p.Executable)) {
	case "codex", "claude", "opencode", "cursor-agent", "gemini", "aider", "grok":
		return true
	}
	return false
}
