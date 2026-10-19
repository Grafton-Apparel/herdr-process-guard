package guard

import (
	"testing"
	"time"

	"github.com/Efeguclu1/herdr-process-guard/internal/model"
	"github.com/Efeguclu1/herdr-process-guard/internal/store"
	"github.com/Efeguclu1/herdr-process-guard/internal/watchdog"
)

func fixtureProcess(pid, ppid int, started time.Time, command string) model.Process {
	return model.Process{Key: model.ProcessKey{PID: pid, StartUnixMS: started.UnixMilli()}, PPID: ppid, PGID: pid, SessionID: 10, UID: 501, Name: "node", Executable: "/usr/bin/node", Command: command, CommandSummary: "node server.js", CommandHash: model.HashCommand(command), CWD: "/repo"}
}

func TestWorkloadRootsStopsAtProtectedInfrastructure(t *testing.T) {
	now := time.Now()
	shell := fixtureProcess(10, 1, now.Add(-time.Hour), "zsh")
	shell.Infrastructure = true
	shell.Protected = true
	agent := fixtureProcess(20, 10, now.Add(-time.Hour), "codex")
	agent.Infrastructure = true
	agent.Protected = true
	server := fixtureProcess(30, 20, now.Add(-time.Hour), "node server.js")
	server.Sockets = []model.Socket{{Protocol: "TCP", Local: "*:5173", Listen: true}}
	processes := map[int]model.Process{10: shell, 20: agent, 30: server}
	roots := workloadRoots(processes, 10, now)
	if len(roots) != 1 || roots[0] != 30 {
		t.Fatalf("expected server root, got %v", roots)
	}
}

func TestOrphanRequiresHistoryEndedAgentAndConfidence(t *testing.T) {
	now := time.Now().UTC()
	process := fixtureProcess(30, 20, now.Add(-2*time.Hour), "node server.js")
	trees := []model.Tree{{RootPID: 30, Processes: []model.Process{process}, Attribution: model.Attribution{AgentStatus: "done", Confidence: model.ConfidenceMedium}, FirstObserved: now.Add(-time.Hour), ObservationCount: 2}}
	classifyTrees(trees, model.NewState(), now, DefaultConfig())
	if trees[0].Lifecycle != model.LifecycleOrphanCandidate {
		t.Fatalf("got %s", trees[0].Lifecycle)
	}
	if trees[0].LeftoverAssessment != model.LeftoverLikely {
		t.Fatalf("expected likely leftover assessment, got %s", trees[0].LeftoverAssessment)
	}

	trees[0].ObservationCount = 1
	trees[0].Evidence = nil
	classifyTrees(trees, model.NewState(), now, DefaultConfig())
	if trees[0].Lifecycle == model.LifecycleOrphanCandidate {
		t.Fatal("single observation must not produce orphan candidate")
	}
}

func TestIntentionalApprovalIsExactTree(t *testing.T) {
	now := time.Now().UTC()
	process := fixtureProcess(30, 20, now.Add(-time.Hour), "node server.js")
	state := model.NewState()
	state.Approvals[process.Key.String()] = model.Approval{Root: process.Key, Members: []model.ProcessKey{process.Key}}
	trees := []model.Tree{{RootPID: 30, Processes: []model.Process{process}, Attribution: model.Attribution{AgentStatus: "done", Confidence: model.ConfidenceMedium}, FirstObserved: now.Add(-time.Hour), ObservationCount: 2}}
	classifyTrees(trees, state, now, DefaultConfig())
	if trees[0].Policy != model.PolicyIntentional {
		t.Fatalf("got %s", trees[0].Policy)
	}
	trees[0].Processes = append(trees[0].Processes, fixtureProcess(31, 30, now, "node worker.js"))
	classifyTrees(trees, state, now, DefaultConfig())
	if trees[0].Policy == model.PolicyIntentional {
		t.Fatal("approval must expire when membership changes")
	}
}

func TestDuplicateListeningServicesAreSuspicious(t *testing.T) {
	now := time.Now()
	first := fixtureProcess(30, 20, now, "node server.js")
	second := fixtureProcess(40, 20, now, "node server.js")
	first.Sockets = []model.Socket{{Listen: true, Local: "*:5173"}}
	second.Sockets = []model.Socket{{Listen: true, Local: "*:5174"}}
	trees := []model.Tree{{RootPID: 30, Processes: []model.Process{first}, Attribution: model.Attribution{WorkspaceID: "w1"}, Policy: model.PolicyUnreviewed}, {RootPID: 40, Processes: []model.Process{second}, Attribution: model.Attribution{WorkspaceID: "w1"}, Policy: model.PolicyUnreviewed}}
	markDuplicateServices(trees)
	if trees[0].Policy != model.PolicySuspicious || trees[1].Policy != model.PolicySuspicious {
		t.Fatalf("duplicates not suspicious: %+v", trees)
	}
}

func TestStopTargetIdentityIncludesCommandAndSession(t *testing.T) {
	key := model.ProcessKey{PID: 30, StartUnixMS: 1000}
	left := []StopTarget{{Key: key, Executable: "node", CommandHash: "a", SessionID: 10}}
	if !sameTargetSet(left, append([]StopTarget(nil), left...)) {
		t.Fatal("equal targets should match")
	}
	right := []StopTarget{{Key: key, Executable: "node", CommandHash: "b", SessionID: 10}}
	if sameTargetSet(left, right) {
		t.Fatal("changed command identity must invalidate preview")
	}
	right[0].CommandHash = "a"
	right[0].SessionID = 11
	if sameTargetSet(left, right) {
		t.Fatal("changed session must invalidate preview")
	}
}

func TestFirstObservationDoesNotTreatHistoricCPUAsRecentActivity(t *testing.T) {
	now := time.Now().UTC()
	process := fixtureProcess(30, 20, now.Add(-time.Hour), "node server.js")
	process.CPUTimeMillis = 90_000
	trees := []model.Tree{{RootPID: 30, Processes: []model.Process{process}, Attribution: model.Attribution{PaneID: "w1:p1", WorkspaceID: "w1"}}}
	state := model.NewState()
	updateObservations(&state, trees, now)
	if trees[0].LastActivity != nil {
		t.Fatalf("historic cumulative CPU incorrectly became activity: %v", trees[0].LastActivity)
	}
}

func TestPaneSessionWithoutAgentHistoryHasLowConfidence(t *testing.T) {
	now := time.Now().UTC()
	process := fixtureProcess(30, 20, now.Add(-time.Hour), "node server.js")
	context := paneContext{}
	context.Pane.PaneID = "w1:p1"
	context.Pane.WorkspaceID = "w1"
	attribution := attributionFor(context, []model.Process{process}, model.NewState(), process.SessionID, false)
	if attribution.Confidence != model.ConfidenceLow {
		t.Fatalf("manual pane process must not be agent-attributed, got %s", attribution.Confidence)
	}
}

func TestDescendantInNewSessionRemainsDiscoverableAndAgentAttributed(t *testing.T) {
	now := time.Now().UTC()
	shell := fixtureProcess(10, 1, now.Add(-time.Hour), "zsh")
	shell.SessionID = 10
	shell.Children = []int{20}
	agent := fixtureProcess(20, 10, now.Add(-time.Hour), "codex")
	agent.SessionID = 10
	agent.Children = []int{30}
	agent.Infrastructure = true
	agent.Protected = true
	agent.ProtectionReason = "coding agent"
	server := fixtureProcess(30, 20, now.Add(-time.Hour), "node server.js")
	server.SessionID = 30
	server.Sockets = []model.Socket{{Protocol: "TCP", Local: "*:5173", Listen: true}}
	processes := map[int]model.Process{10: shell, 20: agent, 30: server}
	descendants := descendantPIDs(processes, 10)
	if len(descendants) != 2 || descendants[1] != 30 {
		t.Fatalf("new-session descendant missing: %v", descendants)
	}
	if !hasAgentAncestor(processes, 30, 10) {
		t.Fatal("server should retain current agent ancestry")
	}
	context := paneContext{}
	context.Pane.PaneID = "w1:p1"
	context.Pane.WorkspaceID = "w1"
	context.Pane.Agent = "codex"
	attribution := attributionFor(context, []model.Process{server}, model.NewState(), shell.SessionID, true)
	if attribution.Confidence != model.ConfidenceHigh {
		t.Fatalf("expected high confidence, got %s", attribution.Confidence)
	}
	if attribution.Relationship != model.RelationshipCurrentAgentAncestry {
		t.Fatalf("expected direct agent relationship, got %s", attribution.Relationship)
	}
	lineage, agentPID := processLineage(processes, server.Key.PID, shell.Key.PID)
	if agentPID != 20 || len(lineage) != 3 {
		t.Fatalf("expected shell -> agent -> workload lineage, got agent %d, %+v", agentPID, lineage)
	}
	if lineage[0].Role != "pane_shell" || lineage[1].Role != "agent" || lineage[2].Role != "workload" {
		t.Fatalf("unexpected lineage roles: %+v", lineage)
	}
}

func TestMonitoringExplainsHistoryMaturity(t *testing.T) {
	now := time.Now().UTC()
	process := fixtureProcess(30, 20, now.Add(-time.Hour), "node server.js")
	trees := []model.Tree{{
		RootPID: 30, Processes: []model.Process{process},
		Attribution:   model.Attribution{AgentStatus: "idle", Confidence: model.ConfidenceHigh},
		FirstObserved: now.Add(-10 * time.Minute), ObservationCount: 2,
	}}
	classifyTrees(trees, model.NewState(), now, DefaultConfig())
	if trees[0].Lifecycle != model.LifecycleIdle || trees[0].LeftoverAssessment != model.LeftoverMonitoring {
		t.Fatalf("expected idle monitoring state, got lifecycle=%s leftover=%s", trees[0].Lifecycle, trees[0].LeftoverAssessment)
	}
	if trees[0].HistoryMaturesAt == nil || !trees[0].HistoryMaturesAt.Equal(now.Add(20*time.Minute)) {
		t.Fatalf("unexpected maturity time: %v", trees[0].HistoryMaturesAt)
	}
}

func TestTinyCPUAdvanceDoesNotKeepIdleServerActive(t *testing.T) {
	now := time.Now().UTC()
	previous := model.Observation{CPUTimeMillis: 1_000, LastObservedAt: now.Add(-5 * time.Second)}
	process := fixtureProcess(30, 20, now.Add(-time.Hour), "node server.js")
	process.CPUTimeMillis = 1_010
	if meaningfulCPUAdvance(previous, process, now) {
		t.Fatal("10ms of CPU housekeeping should not count as activity")
	}
	process.CPUTimeMillis = 1_060
	if !meaningfulCPUAdvance(previous, process, now) {
		t.Fatal("60ms of CPU over five seconds should count as activity")
	}
}

func TestRecordedLineageMarksReparentedProcessDetached(t *testing.T) {
	now := time.Now().UTC()
	process := fixtureProcess(30, 1, now.Add(-time.Hour), "node server.js")
	state := model.NewState()
	state.Observations[process.Key.String()] = model.Observation{Key: process.Key, PaneID: "w1:p1", PPID: 20}
	parent := fixtureProcess(20, 10, now.Add(-2*time.Hour), "codex")
	state.Observations[parent.Key.String()] = model.Observation{Key: parent.Key, PaneID: "w1:p1"}
	processes := map[int]model.Process{30: process}
	annotateRecordedLineage(processes, state, "w1:p1", process.SessionID)
	got := processes[30]
	if !got.Detached || got.RecordedParent == nil || got.RecordedParent.PID != 20 {
		t.Fatalf("recorded lineage missing: %+v", got)
	}
}

func TestRecordedListenerKeepsKnownWorkloadStableWhenSocketTelemetryMisses(t *testing.T) {
	now := time.Now().UTC()
	process := fixtureProcess(30, 20, now.Add(-time.Hour), "node --env-file=.env dist/main.js")
	state := model.NewState()
	state.Observations[process.Key.String()] = model.Observation{
		Key: process.Key, PaneID: "w1:p1", PPID: 20, Ports: []string{"127.0.0.1:8787"},
	}
	processes := map[int]model.Process{30: process}
	annotateRecordedLineage(processes, state, "w1:p1", process.SessionID)
	if !processes[30].RecordedListener || !looksLikeWorkload(processes[30], now) {
		t.Fatalf("known listener should remain a workload during a telemetry miss: %+v", processes[30])
	}
}

func TestInspectorPruningPreservesExactMarkedSurvivorsForWatchdog(t *testing.T) {
	for _, scenario := range []string{"root-live", "root-gone", "root-reused", "child-reused", "all-gone", "both-reused"} {
		t.Run(scenario, func(t *testing.T) {
			t.Setenv("HERDR_PLUGIN_STATE_DIR", t.TempDir())
			now := time.Unix(10000, 0)
			root := fixtureProcess(30, 1, now.Add(-time.Hour), "root")
			child := fixtureProcess(40, 30, now.Add(-time.Hour), "child")
			socket := "/fixture/marked-session/herdr.sock"
			dir, err := store.SessionDirectory(socket)
			if err != nil {
				t.Fatal(err)
			}
			registry := store.New(dir)
			approval := model.Approval{Root: root.Key, Members: []model.ProcessKey{root.Key, child.Key}, MarkedAt: now}
			if _, err := registry.Update(func(state *model.PersistedState) error { state.Approvals[root.Key.String()] = approval; return nil }); err != nil {
				t.Fatal(err)
			}
			live := map[int]model.Process{child.Key.PID: child}
			wantKeep := true
			switch scenario {
			case "root-live":
				live[root.Key.PID] = root
			case "root-reused":
				replacement := root
				replacement.Key.StartUnixMS++
				live[root.Key.PID] = replacement
			case "child-reused":
				replacement := child
				replacement.Key.StartUnixMS++
				live[child.Key.PID] = replacement
				wantKeep = false
			case "all-gone":
				delete(live, child.Key.PID)
				wantKeep = false
			case "both-reused":
				replacement := root
				replacement.Key.StartUnixMS++
				live[root.Key.PID] = replacement
				replacement = child
				replacement.Key.StartUnixMS++
				live[child.Key.PID] = replacement
				wantKeep = false
			}
			collector := watchdog.Collector{Paths: func() ([]string, []string, error) { return nil, nil, nil }, KnownSockets: func() ([]string, error) { return []string{socket}, nil }, Processes: func() (map[int]model.Process, []string, bool, error) { return live, nil, true, nil }}
			before, err := collector.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := registry.Update(func(state *model.PersistedState) error { pruneState(state, live, now, DefaultConfig()); return nil }); err != nil {
				t.Fatal(err)
			}
			saved, err := registry.Load()
			if err != nil {
				t.Fatal(err)
			}
			kept, ok := saved.Approvals[root.Key.String()]
			if ok != wantKeep {
				t.Fatalf("approval retained=%v want %v", ok, wantKeep)
			}
			if wantKeep && (kept.Root != root.Key || len(kept.Members) != 2 || kept.Members[1] != child.Key) {
				t.Fatal("pruning changed approved identities")
			}
			after, err := collector.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			if wantKeep && !after.Intentional[child.Key.String()] {
				t.Fatal("inspector refresh removed surviving exact member protection")
			}
			for _, p := range live {
				if p.Key != root.Key && p.Key != child.Key && after.Intentional[p.Key.String()] {
					t.Fatal("approval transferred to reused PID")
				}
			}
			if !wantKeep && len(after.Intentional) != 0 {
				t.Fatal("dead/reused identities kept current process protection")
			}
			if wantKeep && !before.Intentional[child.Key.String()] {
				t.Fatal("fixture had no initial member protection")
			}
		})
	}
}
