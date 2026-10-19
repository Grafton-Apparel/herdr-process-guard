package watchdog

import (
	"github.com/Efeguclu1/herdr-process-guard/internal/model"
	"testing"
	"time"
)

func proc(pid, parent int, name string) model.Process {
	return model.Process{Key: model.ProcessKey{PID: pid, BootID: "boot", StartTicks: uint64(pid), StartUnixMS: 1}, PPID: parent, UID: 1000, Name: name, Executable: "/bin/" + name, ExecutableInode: uint64(pid), CommandHash: name, TelemetryComplete: true, ChildrenComplete: true, IOComplete: true, SocketsComplete: true}
}
func liveFixture() Snapshot {
	a, b, c := proc(10, 1, "bash"), proc(20, 10, "codex"), proc(30, 20, "helper")
	a.Children = []int{20}
	b.Children = []int{30}
	return Snapshot{Complete: true, GraphComplete: true, Processes: map[int]model.Process{10: a, 20: b, 30: c}, Sessions: []Session{{Socket: "/s", Panes: []Pane{{ID: "p", Shell: a.Key, Agents: []model.ProcessKey{b.Key}, Status: "idle"}}}}}
}
func orphanFixture() Snapshot {
	s := liveFixture()
	p := s.Processes[30]
	p.PPID = 1
	s.Processes = map[int]model.Process{30: p}
	s.Sessions = []Session{{Socket: "/s"}}
	return s
}
func observeMature(t *testing.T, alter func(*Snapshot), restart bool) (State, Snapshot, time.Time) {
	t.Helper()
	c := Defaults()
	now := time.Unix(10000, 0)
	st := NewState()
	Observe(&st, liveFixture(), now, c)
	s := orphanFixture()
	for i := 0; i <= 61; i++ {
		if alter != nil {
			alter(&s)
		}
		if restart && i == 60 {
			ResetContinuity(&st)
		}
		Observe(&st, s, now.Add(time.Duration(i+1)*c.Poll()), c)
	}
	return st, s, now.Add(62 * c.Poll())
}
func TestPreviouslyOwnedHelperOnlyAfterContinuousOrphanhood(t *testing.T) {
	c := Defaults()
	st := NewState()
	now := time.Unix(10000, 0)
	s := liveFixture()
	Observe(&st, s, now, c)
	if len(st.Records) != 1 {
		t.Fatalf("record non-listener helper: %+v", st)
	}
	s = orphanFixture()
	Observe(&st, s, now.Add(c.Poll()), c)
	if got := Candidates(st, s, now.Add(c.Poll()), c); len(got) != 0 {
		t.Fatal("premature orphan", got)
	}
	st, s, now = observeMature(t, nil, false)
	if got := Candidates(st, s, now, c); len(got) != 1 {
		t.Fatalf("mature helper missing: %+v %+v", got, st)
	}
}
func TestRetainedPanesAndAgentsAreProtected(t *testing.T) {
	for _, status := range []string{"idle", "blocked", "working", "unknown", "done"} {
		t.Run(status, func(t *testing.T) {
			s := liveFixture()
			s.Sessions[0].Panes[0].Status = status
			st := NewState()
			now := time.Unix(10000, 0)
			for i := 0; i < 70; i++ {
				Observe(&st, s, now.Add(time.Duration(i)*Defaults().Poll()), Defaults())
			}
			if len(Candidates(st, s, now.Add(time.Hour), Defaults())) != 0 {
				t.Fatal("live pane targeted")
			}
		})
	}
}
func TestSafetyGapsRejectEntireTree(t *testing.T) {
	cases := map[string]func(*Snapshot){"session gap": func(s *Snapshot) { s.Complete = false }, "ancestry gap": func(s *Snapshot) { s.GraphComplete = false }, "target IO": func(s *Snapshot) { p := s.Processes[30]; p.IOComplete = false; s.Processes[30] = p }, "pid reuse": func(s *Snapshot) { p := s.Processes[30]; p.Key.StartTicks++; s.Processes[30] = p }, "exec": func(s *Snapshot) { p := s.Processes[30]; p.ExecutableInode++; s.Processes[30] = p }, "foreign child": func(s *Snapshot) { p := s.Processes[30]; p.Children = []int{999}; s.Processes[30] = p }, "zombie": func(s *Snapshot) { p := s.Processes[30]; p.State = "Z"; s.Processes[30] = p }, "connection": func(s *Snapshot) {
		p := s.Processes[30]
		p.Sockets = []model.Socket{{State: "ESTABLISHED"}}
		s.Processes[30] = p
	}, "intentional": func(s *Snapshot) { s.Intentional = map[string]bool{s.Processes[30].Key.String(): true} }, "new pane": func(s *Snapshot) {
		s.Sessions = append(s.Sessions, Session{Socket: "/other", Panes: []Pane{{ID: "p2", Shell: s.Processes[30].Key}}})
	}}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			st, s, now := observeMature(t, nil, false)
			change(&s)
			Observe(&st, s, now, Defaults())
			if len(Candidates(st, s, now, Defaults())) != 0 {
				t.Fatal("unsafe tree selected")
			}
		})
	}
}
func TestDowntimeAndRestartDoNotCount(t *testing.T) {
	st, s, now := observeMature(t, nil, true)
	if len(Candidates(st, s, now, Defaults())) != 0 {
		t.Fatal("restart retained continuous evidence")
	}
	st, s, now = observeMature(t, nil, false)
	Observe(&st, s, now.Add(time.Hour), Defaults())
	if len(Candidates(st, s, now.Add(time.Hour), Defaults())) != 0 {
		t.Fatal("downtime counted")
	}
}
func TestActivityUpdatesBaselinesAndUnrelatedTelemetryDoesNotBlock(t *testing.T) {
	st, s, now := observeMature(t, nil, false)
	p := proc(70, 1, "other")
	p.IOComplete = false
	s.Processes[70] = p
	if len(Candidates(st, s, now, Defaults())) != 1 {
		t.Fatal("unrelated I/O blocked")
	}
	p = s.Processes[30]
	p.IOReadChars++
	s.Processes[30] = p
	Observe(&st, s, now, Defaults())
	if len(Candidates(st, s, now, Defaults())) != 0 {
		t.Fatal("I/O ignored")
	}
	if st.Records[p.Key.String()].Last.IOReadChars != 1 {
		t.Fatal("baseline not updated")
	}
}
func TestNewChildAndProtectedAncestorBlockTree(t *testing.T) {
	for _, name := range []string{"helper", "bash", "systemd", "codex", "herdr", "herdr-process-guard"} {
		t.Run(name, func(t *testing.T) {
			st, s, now := observeMature(t, nil, false)
			child := proc(31, 30, name)
			p := s.Processes[30]
			p.Children = []int{31}
			s.Processes[30] = p
			s.Processes[31] = child
			if len(Candidates(st, s, now, Defaults())) != 0 {
				t.Fatal("new child accepted")
			}
		})
	}
}
func TestNotificationsCooldownAndResourcesNeverSelectLiveAgent(t *testing.T) {
	c := Defaults()
	st := NewState()
	s := liveFixture()
	now := time.Unix(10000, 0)
	count := 0
	for i := 0; i < 80; i++ {
		p := s.Processes[20]
		p.RSSBytes = c.RSSBytes
		p.CPUTimeMillis += 30000
		s.Processes[20] = p
		events := Observe(&st, s, now.Add(time.Duration(i)*c.Poll()), c)
		for _, e := range events {
			if e.Kind == "resource" {
				count++
			}
		}
	}
	if count != 2 {
		t.Fatalf("resource alert cooldown: %d", count)
	}
	if len(Candidates(st, s, now.Add(time.Hour), c)) != 0 {
		t.Fatal("resource alert permits termination")
	}
}
func TestAttemptIdentitySurvivesReattributionAndStateIsBounded(t *testing.T) {
	st, s, now := observeMature(t, nil, false)
	st.Attempts[s.Processes[30].Key.String()] = true
	if len(Candidates(st, s, now, Defaults())) != 0 {
		t.Fatal("persisted attempt ignored")
	}
	c := Defaults()
	c.MaxRecords = 2
	for i := 100; i < 110; i++ {
		p := proc(i, 1, "other")
		s.Processes[i] = p
	}
	Observe(&st, s, now.Add(c.Poll()), c)
	if len(st.Resources) > c.MaxRecords {
		t.Fatal("unbounded resources")
	}
}
func TestIdlePaneWithoutAgentProcessStillAlerts(t *testing.T) {
	st := NewState()
	s := liveFixture()
	s.Sessions[0].Panes[0].Agents = nil
	s.Sessions[0].Panes[0].IsAgent = true
	c := Defaults()
	now := time.Unix(10000, 0)
	count := 0
	for i := 0; i <= 481; i++ {
		events := Observe(&st, s, now.Add(time.Duration(i)*c.Poll()), c)
		for _, e := range events {
			if e.Kind == "idle-pane" {
				count++
			}
		}
	}
	if count != 1 {
		t.Fatalf("idle alert count %d", count)
	}
}
func TestResourceAlertsContinueAcrossUnrelatedSessionGaps(t *testing.T) {
	st := NewState()
	s := liveFixture()
	s.Complete = false
	s.GraphComplete = false
	c := Defaults()
	now := time.Unix(10000, 0)
	count := 0
	for i := 0; i < 12; i++ {
		p := s.Processes[20]
		p.RSSBytes = c.RSSBytes
		s.Processes[20] = p
		for _, e := range Observe(&st, s, now.Add(time.Duration(i)*c.Poll()), c) {
			if e.Kind == "resource" {
				count++
			}
		}
	}
	if count != 1 {
		t.Fatal("resource alerts suppressed by unrelated snapshot gap", count)
	}
}

func TestResourceAlertsWithTargetTelemetryGapsKeepCleanupBlocked(t *testing.T) {
	for _, metric := range []string{"CPU", "RSS"} {
		for _, gap := range []string{"socket", "I/O"} {
			t.Run(metric+"/"+gap, func(t *testing.T) {
				c := Defaults()
				st := NewState()
				now := time.Unix(10000, 0)
				Observe(&st, liveFixture(), now, c)
				s := orphanFixture()
				count := 0
				for i := 1; i <= 63; i++ {
					p := s.Processes[30]
					p.TelemetryComplete = false
					if gap == "socket" {
						p.SocketsComplete = false
					} else {
						p.IOComplete = false
					}
					if metric == "CPU" {
						p.CPUTimeMillis += int64(c.PollSeconds) * 1000
					} else {
						p.RSSBytes = c.RSSBytes
					}
					s.Processes[30] = p
					at := now.Add(time.Duration(i) * c.Poll())
					for _, event := range Observe(&st, s, at, c) {
						if event.Kind == "resource" && event.PID == 30 {
							count++
						}
					}
					if len(Candidates(st, s, at, c)) != 0 {
						t.Fatal("target telemetry gap permitted cleanup")
					}
				}
				if count != 1 {
					t.Fatalf("sustained %s alert with %s gap: got %d want 1", metric, gap, count)
				}
			})
		}
	}
}

func TestResourceAlertsUseStatIdentityDuringExecutableGaps(t *testing.T) {
	c := Defaults()
	st := NewState()
	s := liveFixture()
	now := time.Unix(10000, 0)
	count := 0
	for i := 0; i < 12; i++ {
		p := s.Processes[30]
		p.RSSBytes = c.RSSBytes
		p.TelemetryComplete = false
		if i%2 == 0 {
			p.Executable = ""
			p.ExecutableInode = 0
			p.CommandHash = ""
		} else {
			p.Executable = "/bin/helper"
			p.ExecutableInode = 30
			p.CommandHash = "helper"
		}
		s.Processes[30] = p
		for _, event := range Observe(&st, s, now.Add(time.Duration(i)*c.Poll()), c) {
			if event.Kind == "resource" && event.PID == 30 {
				count++
			}
		}
	}
	if count != 1 {
		t.Fatalf("stat identity lost resource history across metadata gaps: %d alerts", count)
	}
}
