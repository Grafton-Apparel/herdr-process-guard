// Package watchdog implements conservative observation policy separately from host I/O.
package watchdog

import (
	"fmt"
	"github.com/Efeguclu1/herdr-process-guard/internal/model"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"
)

type Pane struct {
	ID      string
	Shell   model.ProcessKey
	Agents  []model.ProcessKey
	Status  string
	IsAgent bool
}
type Session struct {
	Socket string
	Panes  []Pane
}
type Snapshot struct {
	Complete, GraphComplete bool
	Processes               map[int]model.Process
	Sessions                []Session
	Intentional             map[string]bool
	Warnings                []string
}
type Record struct {
	Last        model.Process    `json:"last"`
	Socket      string           `json:"socket"`
	Pane        string           `json:"pane"`
	Shell       model.ProcessKey `json:"shell"`
	Agent       model.ProcessKey `json:"agent"`
	Seen        time.Time        `json:"seen"`
	OrphanSince time.Time        `json:"orphan_since,omitempty"`
	QuietSince  time.Time        `json:"quiet_since,omitempty"`
	Attempted   bool             `json:"attempted,omitempty"`
}
type Resource struct {
	Last        model.Process
	Seen, Since time.Time
}
type State struct {
	Attempts  map[string]bool      `json:"attempts"`
	Records   map[string]Record    `json:"records"`
	Resources map[string]Resource  `json:"resources"`
	Cooldowns map[string]time.Time `json:"cooldowns"`
	Idle      map[string]time.Time `json:"idle"`
	LastPoll  time.Time            `json:"last_poll"`
	Paused    bool                 `json:"paused"`
	Warnings  []string             `json:"warnings,omitempty"`
}
type Event struct {
	Kind    string    `json:"kind"`
	Key     string    `json:"key"`
	Socket  string    `json:"socket,omitempty"`
	Pane    string    `json:"pane,omitempty"`
	PID     int       `json:"pid,omitempty"`
	Summary string    `json:"summary"`
	At      time.Time `json:"at"`
}
type Candidate struct {
	Root         int
	Members      []model.Process
	Socket, Pane string
}

func NewState() State {
	return State{Attempts: map[string]bool{}, Records: map[string]Record{}, Resources: map[string]Resource{}, Cooldowns: map[string]time.Time{}, Idle: map[string]time.Time{}}
}

// ResetContinuity preserves exact attribution, attempts, and cooldowns, but counts no downtime.
func ResetContinuity(st *State) {
	st.LastPoll = time.Time{}
	st.Resources = map[string]Resource{}
	st.Idle = map[string]time.Time{}
	for k, r := range st.Records {
		r.OrphanSince = time.Time{}
		r.QuietSince = time.Time{}
		r.Seen = time.Time{}
		st.Records[k] = r
	}
}
func exact(a, b model.Process) bool {
	return a.Key == b.Key && a.UID == b.UID && a.Executable == b.Executable && a.ExecutableDevice == b.ExecutableDevice && a.ExecutableInode == b.ExecutableInode && a.CommandHash == b.CommandHash
}
func alive(s Snapshot, k model.ProcessKey) bool { p, ok := s.Processes[k.PID]; return ok && p.Key == k }
func protected(p model.Process) bool {
	n := strings.ToLower(filepath.Base(p.Executable))
	if n == "" || n == "." {
		n = strings.ToLower(p.Name)
	}
	switch n {
	case "bash", "zsh", "sh", "dash", "fish", "nu", "pwsh", "systemd", "init", "herdr", "herdr-process-guard", "codex", "claude", "cursor-agent", "opencode", "gemini", "aider", "grok", "containerd", "dockerd", "runc", "runsvc.sh", "runner.listener", "runner.worker":
		return true
	}
	return p.Protected || p.Infrastructure
}
func ancestor(s Snapshot, pid, root int) bool {
	seen := map[int]bool{}
	for pid > 0 && !seen[pid] {
		if pid == root {
			return true
		}
		seen[pid] = true
		p, ok := s.Processes[pid]
		if !ok {
			return false
		}
		pid = p.PPID
	}
	return false
}
func protectedByPane(s Snapshot, p model.Process) bool {
	for _, session := range s.Sessions {
		for _, pane := range session.Panes {
			if alive(s, pane.Shell) && (ancestor(s, p.Key.PID, pane.Shell.PID) || p.SessionID != 0 && p.SessionID == s.Processes[pane.Shell.PID].SessionID) {
				return true
			}
			for _, a := range pane.Agents {
				if alive(s, a) && ancestor(s, p.Key.PID, a.PID) {
					return true
				}
			}
		}
	}
	return false
}
func marked(s Snapshot, p model.Process) bool {
	seen := map[int]bool{}
	pid := p.Key.PID
	for pid > 0 && !seen[pid] {
		seen[pid] = true
		q, ok := s.Processes[pid]
		if !ok {
			break
		}
		if s.Intentional[q.Key.String()] {
			return true
		}
		pid = q.PPID
	}
	return false
}
func ownerGone(s Snapshot, r Record) bool {
	for _, ss := range s.Sessions {
		if ss.Socket == r.Socket {
			for _, p := range ss.Panes {
				if p.ID == r.Pane {
					return false
				}
			}
		}
	}
	return !alive(s, r.Shell) && !alive(s, r.Agent)
}
func telemetry(p model.Process) bool {
	return p.TelemetryComplete && p.ChildrenComplete && p.IOComplete && p.SocketsComplete && p.UID >= 0 && p.Key.BootID != "" && p.Key.StartTicks > 0 && p.ExecutableInode > 0 && !strings.Contains(p.State, "Z")
}
func active(a, b model.Process, c Config) bool {
	return b.CPUTimeMillis < a.CPUTimeMillis || b.CPUTimeMillis-a.CPUTimeMillis > c.CPUActivityMillis || a.IOReadBytes != b.IOReadBytes || a.IOWriteBytes != b.IOWriteBytes || a.IOReadChars != b.IOReadChars || a.IOWriteChars != b.IOWriteChars || b.HasEstablishedConnection()
}
func Observe(st *State, s Snapshot, now time.Time, c Config) []Event {
	events := []Event{}
	emit := func(e Event) {
		e.At = now
		if last, ok := st.Cooldowns[e.Key]; ok && now.Sub(last) < c.Cooldown() {
			return
		}
		st.Cooldowns[e.Key] = now
		events = append(events, e)
	}
	continuous := !st.LastPoll.IsZero() && now.After(st.LastPoll) && now.Sub(st.LastPoll) <= 2*c.Poll()
	if !continuous {
		ResetContinuity(st)
	}
	st.Warnings = append([]string(nil), s.Warnings...)
	if !s.Complete || !s.GraphComplete {
		st.Warnings = append(st.Warnings, "cleanup suspended: incomplete session or ancestry snapshot")
		emit(Event{Kind: "gap", Key: "snapshot-gap", Summary: "Cleanup suspended: incomplete session or ancestry snapshot"})
	}
	// Only exact observed ancestry beneath an identified pane agent establishes ownership.
	if s.Complete && s.GraphComplete {
		for _, ss := range s.Sessions {
			for _, pane := range ss.Panes {
				if !alive(s, pane.Shell) {
					continue
				}
				for _, a := range pane.Agents {
					if !alive(s, a) || !ancestor(s, a.PID, pane.Shell.PID) {
						continue
					}
					for _, p := range s.Processes {
						if p.Key == a || protected(p) || !ancestor(s, p.Key.PID, a.PID) {
							continue
						}
						k := p.Key.String()
						old, exists := st.Records[k]
						if exists && (!exact(old.Last, p) || old.Socket != ss.Socket || old.Pane != pane.ID || old.Shell != pane.Shell || old.Agent != a) {
							delete(st.Records, k)
							continue
						}
						if !exists {
							st.Records[k] = Record{Last: p, Socket: ss.Socket, Pane: pane.ID, Shell: pane.Shell, Agent: a}
						}
					}
				}
			}
		}
	}
	for k, r := range st.Records {
		p, ok := s.Processes[r.Last.Key.PID]
		if !ok || !exact(r.Last, p) {
			delete(st.Records, k)
			continue
		}
		safe := s.Complete && s.GraphComplete && telemetry(p) && !protected(p) && !protectedByPane(s, p) && !marked(s, p) && ownerGone(s, r)
		if !safe {
			r.OrphanSince = time.Time{}
			r.QuietSince = time.Time{}
		} else {
			if r.OrphanSince.IsZero() {
				r.OrphanSince = now
			}
			if r.QuietSince.IsZero() || r.Seen.IsZero() || active(r.Last, p, c) {
				r.QuietSince = now
			}
			emit(Event{Kind: "orphan", Key: "orphan:" + k, Socket: r.Socket, Pane: r.Pane, PID: p.Key.PID, Summary: summary(p)})
		}
		r.Last = p
		r.Seen = now
		st.Records[k] = r
	}
	for _, p := range s.Processes {
		k := p.Key.String()
		old, ok := st.Resources[k]
		high := p.RSSBytes >= c.RSSBytes
		if ok && continuous && exact(old.Last, p) && now.After(old.Seen) {
			cpu := float64(p.CPUTimeMillis-old.Last.CPUTimeMillis) / float64(now.Sub(old.Seen).Milliseconds()) * 100
			high = high || cpu >= c.CPUPercent
		}
		r := Resource{Last: p, Seen: now}
		if high && telemetry(p) {
			r.Since = old.Since
			if !ok || !continuous || !exact(old.Last, p) || r.Since.IsZero() {
				r.Since = now
			}
			if now.Sub(r.Since) >= c.ResourceWindow() {
				emit(Event{Kind: "resource", Key: "resource:" + k, PID: p.Key.PID, Summary: summary(p)})
			}
		}
		st.Resources[k] = r
	}
	idleSeen := map[string]bool{}
	for _, ss := range s.Sessions {
		for _, p := range ss.Panes {
			k := ss.Socket + ":" + p.ID
			if len(p.Agents) == 0 && !p.IsAgent || p.Status == "working" {
				delete(st.Idle, k)
				continue
			}
			idleSeen[k] = true
			if st.Idle[k].IsZero() {
				st.Idle[k] = now
			}
			if now.Sub(st.Idle[k]) >= c.IdleWindow() {
				emit(Event{Kind: "idle-pane", Key: "idle:" + k, Socket: ss.Socket, Pane: p.ID, Summary: "Retained agent pane has remained idle or blocked; pane stays open"})
			}
		}
	}
	for k := range st.Idle {
		if !idleSeen[k] {
			delete(st.Idle, k)
		}
	}
	// Bounds retain only live identities; cooldowns expire. Attribution eviction can only disable cleanup.
	for k, r := range st.Resources {
		if p, ok := s.Processes[r.Last.Key.PID]; !ok || p.Key != r.Last.Key {
			delete(st.Resources, k)
		}
	}
	for k, at := range st.Cooldowns {
		if now.Sub(at) > 24*time.Hour {
			delete(st.Cooldowns, k)
		}
	}
	if len(st.Records) > c.MaxRecords {
		keys := make([]string, 0, len(st.Records))
		for k := range st.Records {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys[:len(keys)-c.MaxRecords] {
			delete(st.Records, k)
		}
	}
	for k := range st.Attempts {
		found := false
		for _, p := range s.Processes {
			if p.Key.String() == k {
				found = true
				break
			}
		}
		if !found && s.Complete && s.GraphComplete {
			delete(st.Attempts, k)
		}
	}
	if len(st.Resources) > c.MaxRecords {
		keys := make([]string, 0, len(st.Resources))
		for k := range st.Resources {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys[c.MaxRecords:] {
			delete(st.Resources, k)
		}
	}
	if len(st.Cooldowns) > 3*c.MaxRecords {
		keys := make([]string, 0, len(st.Cooldowns))
		for k := range st.Cooldowns {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return st.Cooldowns[keys[i]].Before(st.Cooldowns[keys[j]]) })
		for _, k := range keys[:len(keys)-3*c.MaxRecords] {
			delete(st.Cooldowns, k)
		}
	}
	st.LastPoll = now
	return events
}
func summary(p model.Process) string {
	s := p.CommandSummary
	if s == "" {
		s = filepath.Base(p.Executable)
	}
	return fmt.Sprintf("PID %d %s", p.Key.PID, SafeText(s))
}

// SafeText omits control bytes, truncates context and never includes raw argv.
func SafeText(s string) string {
	r := []rune{}
	for _, c := range s {
		if c >= 32 && c != 127 {
			r = append(r, c)
		}
		if len(r) >= 120 {
			break
		}
	}
	return string(r)
}
func Candidates(st State, s Snapshot, now time.Time, c Config) []Candidate {
	if !s.Complete || !s.GraphComplete {
		return nil
	}
	result := []Candidate{}
	selected := map[int]bool{}
	keys := make([]string, 0, len(st.Records))
	for k := range st.Records {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return st.Records[keys[i]].Last.Key.PID < st.Records[keys[j]].Last.Key.PID })
	for _, key := range keys {
		r := st.Records[key]
		p, ok := s.Processes[r.Last.Key.PID]
		if !ok || selected[p.Key.PID] {
			continue
		}
		if parent, ok := s.Processes[p.PPID]; ok {
			if _, known := st.Records[parent.Key.String()]; known {
				continue
			}
		}
		members := []model.Process{}
		seen := map[int]bool{}
		valid := true
		var walk func(int)
		walk = func(pid int) {
			if seen[pid] {
				valid = false
				return
			}
			seen[pid] = true
			p, ok := s.Processes[pid]
			if !ok {
				valid = false
				return
			}
			o, ok := st.Records[p.Key.String()]
			if !ok || !exact(o.Last, p) || o.Socket != r.Socket || o.Pane != r.Pane || o.Attempted || st.Attempts[p.Key.String()] || o.Seen.IsZero() || now.Before(o.Seen) || now.Sub(o.Seen) > 2*c.Poll() || o.OrphanSince.IsZero() || now.Sub(o.OrphanSince) < c.OrphanWindow() || o.QuietSince.IsZero() || now.Sub(o.QuietSince) < c.OrphanWindow() || !ownerGone(s, o) || protectedByPane(s, p) || protected(p) || marked(s, p) || !telemetry(p) || active(o.Last, p, c) {
				valid = false
			}
			members = append(members, p)
			for _, id := range p.Children {
				q, ok := s.Processes[id]
				if !ok || q.PPID != pid {
					valid = false
				}
				walk(id)
			}
			for id, q := range s.Processes {
				if q.PPID == pid && !contains(p.Children, id) {
					valid = false
				}
			}
		}
		walk(p.Key.PID)
		// Adoption by PID 1 is allowed. Other protected or intentional ancestors keep the tree.
		for pid := p.PPID; pid > 1; {
			q, ok := s.Processes[pid]
			if !ok {
				valid = false
				break
			}
			if protected(q) || marked(s, q) {
				valid = false
			}
			if seen[pid] {
				valid = false
				break
			}
			seen[pid] = true
			pid = q.PPID
		}
		if valid {
			sort.Slice(members, func(i, j int) bool { return members[i].Key.PID < members[j].Key.PID })
			result = append(result, Candidate{Root: p.Key.PID, Members: members, Socket: r.Socket, Pane: r.Pane})
			for _, m := range members {
				selected[m.Key.PID] = true
			}
		}
	}
	return result
}
func contains(ids []int, id int) bool {
	for _, v := range ids {
		if v == id {
			return true
		}
	}
	return false
}
func SameCandidate(a, b Candidate) bool {
	return a.Root == b.Root && a.Socket == b.Socket && a.Pane == b.Pane && reflect.DeepEqual(a.Members, b.Members)
}
