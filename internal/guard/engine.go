package guard

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Efeguclu1/herdr-process-guard/internal/herdr"
	"github.com/Efeguclu1/herdr-process-guard/internal/model"
	"github.com/Efeguclu1/herdr-process-guard/internal/platform"
	"github.com/Efeguclu1/herdr-process-guard/internal/store"
)

type Engine struct {
	Herdr   *herdr.Client
	Scanner *platform.Scanner
	Store   *store.Store
	Config  Config
	Now     func() time.Time
}

func New() (*Engine, error) {
	client, err := herdr.NewFromEnvironment()
	if err != nil {
		return nil, err
	}
	directory, err := store.SessionDirectory(client.SocketPath)
	if err != nil {
		return nil, fmt.Errorf("resolve state directory: %w", err)
	}
	return &Engine{Herdr: client, Scanner: platform.NewScanner(), Store: store.New(directory), Config: DefaultConfig(), Now: time.Now}, nil
}

type paneContext struct {
	Pane      herdr.Pane
	Tab       herdr.Tab
	Workspace herdr.Workspace
	Info      herdr.ProcessInfo
	Agent     *herdr.Agent
}

func (e *Engine) Scan(reason string) (model.Report, error) {
	now := e.Now().UTC()
	snapshot, err := e.Herdr.SessionSnapshot()
	if err != nil {
		return model.Report{}, err
	}
	processes, warnings, err := e.Scanner.Processes()
	if err != nil {
		return model.Report{}, err
	}
	previous, err := e.Store.Load()
	if err != nil {
		return model.Report{}, err
	}
	contexts, contextWarnings := e.paneContexts(snapshot)
	warnings = append(warnings, contextWarnings...)
	trees := buildTrees(contexts, processes, previous, now, os.Getpid())

	updated, err := e.Store.Update(func(state *model.PersistedState) error {
		updateAgentIntervals(state, contexts, now)
		updateObservations(state, trees, now)
		pruneState(state, processes, now, e.Config)
		return nil
	})
	if err != nil {
		return model.Report{}, err
	}
	classifyTrees(trees, updated, now, e.Config)
	markDuplicateServices(trees)
	sort.Slice(trees, func(i, j int) bool {
		if trees[i].Attribution.WorkspaceID != trees[j].Attribution.WorkspaceID {
			return trees[i].Attribution.WorkspaceID < trees[j].Attribution.WorkspaceID
		}
		if trees[i].Attribution.PaneID != trees[j].Attribution.PaneID {
			return trees[i].Attribution.PaneID < trees[j].Attribution.PaneID
		}
		return trees[i].RootPID < trees[j].RootPID
	})
	report := model.Report{SchemaVersion: model.SchemaVersion, ObservedAt: now, Trees: trees, Warnings: warnings}
	report.Summary = summarize(trees)
	if reason != "" && reason != "scan" {
		report.Warnings = append(report.Warnings, "snapshot reason: "+reason)
	}
	return report, nil
}

func (e *Engine) paneContexts(snapshot herdr.Snapshot) ([]paneContext, []string) {
	workspaces := map[string]herdr.Workspace{}
	for _, workspace := range snapshot.Workspaces {
		workspaces[workspace.WorkspaceID] = workspace
	}
	agents := map[string]herdr.Agent{}
	for _, agent := range snapshot.Agents {
		agents[agent.PaneID] = agent
	}
	tabs := map[string]herdr.Tab{}
	for _, tab := range snapshot.Tabs {
		tabs[tab.TabID] = tab
	}
	contexts := make([]paneContext, 0, len(snapshot.Panes))
	warnings := []string{}
	for _, pane := range snapshot.Panes {
		info, err := e.Herdr.PaneProcessInfo(pane.PaneID)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("pane %s process information unavailable: %v", pane.PaneID, err))
			continue
		}
		context := paneContext{Pane: pane, Tab: tabs[pane.TabID], Workspace: workspaces[pane.WorkspaceID], Info: info}
		if agent, ok := agents[pane.PaneID]; ok {
			context.Agent = &agent
		}
		contexts = append(contexts, context)
	}
	return contexts, warnings
}

func buildTrees(contexts []paneContext, processes map[int]model.Process, state model.PersistedState, now time.Time, ownPID int) []model.Tree {
	trees := []model.Tree{}
	seenRoots := map[string]bool{}
	for _, context := range contexts {
		if context.Info.ShellPID == nil {
			continue
		}
		shell, exists := processes[*context.Info.ShellPID]
		if !exists {
			continue
		}
		members := map[int]model.Process{}
		for pid, process := range processes {
			if process.SessionID == shell.SessionID {
				members[pid] = process
			}
		}
		// Servers commonly call setsid(2), creating a new OS session while
		// remaining descendants of the pane shell or agent. Current ancestry is
		// direct attribution evidence and must not be discarded by the session
		// filter.
		for _, pid := range descendantPIDs(processes, shell.Key.PID) {
			members[pid] = processes[pid]
		}
		// Preserve exact previously observed identities even after re-parenting or setsid.
		for _, observation := range state.Observations {
			if observation.PaneID != context.Pane.PaneID {
				continue
			}
			if process, ok := processes[observation.Key.PID]; ok && process.Key == observation.Key {
				members[process.Key.PID] = process
			}
		}
		markInfrastructure(members, shell.Key.PID, context.Info, ownPID)
		annotateRecordedLineage(members, state, context.Pane.PaneID, shell.SessionID)
		candidateRoots := workloadRoots(members, shell.Key.PID, now)
		for _, rootPID := range candidateRoots {
			key := context.Pane.PaneID + ":" + fmt.Sprint(rootPID)
			if seenRoots[key] {
				continue
			}
			seenRoots[key] = true
			treeProcesses := subtree(members, rootPID)
			if len(treeProcesses) == 0 {
				continue
			}
			lineage, agentPID := processLineage(members, rootPID, shell.Key.PID)
			agentDescendant := agentPID != 0
			attribution := attributionFor(context, treeProcesses, state, shell.SessionID, agentDescendant)
			attribution.ShellPID = shell.Key.PID
			attribution.AgentPID = agentPID
			attribution.Lineage = lineage
			trees = append(trees, model.Tree{RootPID: rootPID, Processes: treeProcesses, Attribution: attribution})
		}
	}
	return trees
}

func descendantPIDs(processes map[int]model.Process, rootPID int) []int {
	result := []int{}
	queue := append([]int(nil), processes[rootPID].Children...)
	seen := map[int]bool{}
	for len(queue) > 0 {
		pid := queue[0]
		queue = queue[1:]
		if seen[pid] {
			continue
		}
		seen[pid] = true
		process, ok := processes[pid]
		if !ok {
			continue
		}
		result = append(result, pid)
		queue = append(queue, process.Children...)
	}
	return result
}

func hasAgentAncestor(processes map[int]model.Process, pid, shellPID int) bool {
	_, agentPID := processLineage(processes, pid, shellPID)
	return agentPID != 0
}

func processLineage(processes map[int]model.Process, pid, shellPID int) ([]model.LineageProcess, int) {
	seen := map[int]bool{}
	reversed := []model.LineageProcess{}
	agentPID := 0
	for pid > 0 && !seen[pid] {
		seen[pid] = true
		process, ok := processes[pid]
		if !ok {
			break
		}
		role := "wrapper"
		if pid == shellPID {
			role = "pane_shell"
		} else if process.ProtectionReason == "coding agent" || process.ProtectionReason == "active coding agent" {
			role = "agent"
			agentPID = pid
		} else if len(reversed) == 0 {
			role = "workload"
		}
		name := process.Name
		if name == "" {
			name = process.CommandSummary
		}
		reversed = append(reversed, model.LineageProcess{PID: pid, Name: name, Role: role})
		if pid == shellPID {
			break
		}
		pid = process.PPID
	}
	lineage := make([]model.LineageProcess, len(reversed))
	for index := range reversed {
		lineage[len(reversed)-1-index] = reversed[index]
	}
	return lineage, agentPID
}

func annotateRecordedLineage(processes map[int]model.Process, state model.PersistedState, paneID string, paneSessionID int) {
	for pid, process := range processes {
		observation, observed := state.Observations[process.Key.String()]
		if process.SessionID != paneSessionID {
			process.Detached = true
		}
		if observed && len(observation.Ports) > 0 {
			process.RecordedListener = true
		}
		if observed && observation.PPID != process.PPID {
			process.Detached = true
			for _, parent := range state.Observations {
				if parent.PaneID == paneID && parent.Key.PID == observation.PPID {
					key := parent.Key
					process.RecordedParent = &key
					break
				}
			}
		}
		processes[pid] = process
	}
}

func markInfrastructure(processes map[int]model.Process, shellPID int, info herdr.ProcessInfo, ownPID int) {
	for pid, process := range processes {
		name := strings.ToLower(process.Name)
		reason := ""
		switch {
		case pid == shellPID:
			reason = "Herdr pane shell"
		case pid == ownPID:
			reason = "Process Guard"
		case isShell(name):
			reason = "shell infrastructure"
		case isAgent(name, process.Command):
			reason = "coding agent"
		}
		for _, foreground := range info.ForegroundProcesses {
			if foreground.PID == pid && isAgent(strings.ToLower(foreground.Name), foreground.Cmdline) {
				reason = "active coding agent"
			}
		}
		if reason != "" {
			process.Infrastructure = true
			process.Protected = true
			process.ProtectionReason = reason
			processes[pid] = process
		}
	}
}

func isShell(name string) bool {
	return name == "zsh" || name == "bash" || name == "sh" || name == "fish" || name == "nu" || name == "pwsh"
}

func isAgent(name, command string) bool {
	lower := strings.ToLower(command)
	for _, marker := range []string{"codex", "claude", "opencode", "cursor-agent", "gemini", "aider", "grok"} {
		if name == marker || strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func looksLikeWorkload(process model.Process, now time.Time) bool {
	if process.Infrastructure || process.Protected {
		return false
	}
	if process.HasListener() || process.RecordedListener {
		return true
	}
	if now.Sub(time.UnixMilli(process.Key.StartUnixMS)) < 5*time.Minute {
		return false
	}
	lower := strings.ToLower(process.Command)
	for _, marker := range []string{"vite", "next dev", "http.server", "uvicorn", "gunicorn", "rails server", "django", "npm run dev", "pnpm run dev", "yarn dev", "bun run dev", "cargo run", "go run"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func workloadRoots(processes map[int]model.Process, shellPID int, now time.Time) []int {
	rootSet := map[int]bool{}
	for pid, process := range processes {
		if !looksLikeWorkload(process, now) {
			continue
		}
		root := pid
		for {
			parent, ok := processes[processes[root].PPID]
			if !ok || parent.Key.PID == shellPID || parent.Infrastructure || parent.Protected {
				break
			}
			root = parent.Key.PID
		}
		rootSet[root] = true
	}
	// Remove nested candidates when an outer workload root already contains them.
	for root := range rootSet {
		for other := range rootSet {
			if root != other && isDescendant(processes, root, other) {
				delete(rootSet, root)
				break
			}
		}
	}
	roots := make([]int, 0, len(rootSet))
	for root := range rootSet {
		roots = append(roots, root)
	}
	sort.Ints(roots)
	return roots
}

func isDescendant(processes map[int]model.Process, pid, possibleAncestor int) bool {
	visited := map[int]bool{}
	for pid > 0 && !visited[pid] {
		visited[pid] = true
		process, ok := processes[pid]
		if !ok {
			return false
		}
		if process.PPID == possibleAncestor {
			return true
		}
		pid = process.PPID
	}
	return false
}

func subtree(processes map[int]model.Process, rootPID int) []model.Process {
	queue := []int{rootPID}
	seen := map[int]bool{}
	result := []model.Process{}
	for len(queue) > 0 {
		pid := queue[0]
		queue = queue[1:]
		if seen[pid] {
			continue
		}
		seen[pid] = true
		process, ok := processes[pid]
		if !ok {
			continue
		}
		result = append(result, process)
		queue = append(queue, process.Children...)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Key.PID < result[j].Key.PID })
	return result
}

func attributionFor(context paneContext, processes []model.Process, state model.PersistedState, paneSessionID int, currentAgentDescendant bool) model.Attribution {
	agentName := context.Pane.DisplayAgent
	if agentName == "" {
		agentName = context.Pane.Agent
	}
	agentStatus := context.Pane.AgentStatus
	agentSession := context.Pane.AgentSession
	if context.Agent != nil {
		if context.Agent.DisplayAgent != "" {
			agentName = context.Agent.DisplayAgent
		} else if context.Agent.Agent != "" {
			agentName = context.Agent.Agent
		}
		agentStatus = context.Agent.AgentStatus
		if context.Agent.AgentSession != nil {
			agentSession = context.Agent.AgentSession
		}
	}
	confidence := model.ConfidenceLow
	method := "pane session only"
	relationship := model.RelationshipUnproven
	if currentAgentDescendant {
		confidence = model.ConfidenceHigh
		method = "current process ancestry passes through the coding agent"
		relationship = model.RelationshipCurrentAgentAncestry
	}
	hasAgentHistory := agentName != ""
	for _, interval := range state.AgentIntervals {
		if interval.PaneID == context.Pane.PaneID {
			hasAgentHistory = true
			break
		}
	}
	for _, process := range processes {
		if currentAgentDescendant {
			break
		}
		for _, interval := range state.AgentIntervals {
			if interval.PaneID != context.Pane.PaneID {
				continue
			}
			started := time.UnixMilli(process.Key.StartUnixMS)
			if started.Before(interval.StartedAt.Add(-2 * time.Minute)) {
				continue
			}
			if interval.EndedAt == nil || !started.After(interval.EndedAt.Add(30*time.Second)) {
				confidence = model.ConfidenceHigh
				method = "process start falls within recorded agent interval"
				relationship = model.RelationshipRecordedAgentWindow
				agentName = interval.Agent
				break
			}
		}
		if confidence == model.ConfidenceHigh {
			break
		}
		if process.SessionID == paneSessionID && hasAgentHistory {
			confidence = model.ConfidenceMedium
			method = "process shares the Herdr pane OS session"
			relationship = model.RelationshipSharedPaneSession
		}
	}
	workspaceCWD := context.Pane.CWD
	if context.Workspace.Worktree != nil {
		workspaceCWD = context.Workspace.Worktree.CheckoutPath
	}
	paneCWD := context.Pane.ForegroundCWD
	if paneCWD == "" {
		paneCWD = context.Pane.CWD
	}
	return model.Attribution{WorkspaceID: context.Pane.WorkspaceID, WorkspaceName: context.Workspace.Label,
		WorkspaceCWD: workspaceCWD, PaneID: context.Pane.PaneID, TabID: context.Pane.TabID,
		TabLabel: context.Tab.Label, PaneLabel: context.Pane.Label, PaneTitle: context.Pane.TerminalTitle,
		PaneCWD: paneCWD, Agent: agentName,
		AgentStatus: agentStatus, AgentSession: agentSession, Confidence: confidence, Method: method,
		Relationship: relationship}
}

func updateAgentIntervals(state *model.PersistedState, contexts []paneContext, now time.Time) {
	seen := map[string]paneContext{}
	for _, context := range contexts {
		seen[context.Pane.PaneID] = context
		name := context.Pane.DisplayAgent
		if name == "" {
			name = context.Pane.Agent
		}
		status := context.Pane.AgentStatus
		if context.Agent != nil {
			if context.Agent.DisplayAgent != "" {
				name = context.Agent.DisplayAgent
			} else if context.Agent.Agent != "" {
				name = context.Agent.Agent
			}
			status = context.Agent.AgentStatus
		}
		open := openInterval(state.AgentIntervals, context.Pane.PaneID)
		active := name != "" && status != "done" && status != "idle"
		if active && open == nil {
			state.AgentIntervals = append(state.AgentIntervals, model.AgentInterval{PaneID: context.Pane.PaneID, Agent: name, Session: sessionValue(context.Pane.AgentSession), StartedAt: now})
		} else if !active && open != nil {
			open.EndedAt = &now
		}
	}
	for index := range state.AgentIntervals {
		interval := &state.AgentIntervals[index]
		if interval.EndedAt == nil {
			if _, ok := seen[interval.PaneID]; !ok {
				interval.EndedAt = &now
			}
		}
	}
}

func openInterval(intervals []model.AgentInterval, paneID string) *model.AgentInterval {
	for index := len(intervals) - 1; index >= 0; index-- {
		if intervals[index].PaneID == paneID && intervals[index].EndedAt == nil {
			return &intervals[index]
		}
	}
	return nil
}

func sessionValue(session *model.AgentSession) string {
	if session == nil {
		return ""
	}
	return session.Value
}

func updateObservations(state *model.PersistedState, trees []model.Tree, now time.Time) {
	for treeIndex := range trees {
		tree := &trees[treeIndex]
		first := now
		count := 0
		var lastActivity *time.Time
		lastActivityReason := ""
		for _, process := range tree.Processes {
			key := process.Key.String()
			previous, exists := state.Observations[key]
			observation := previous
			if !exists {
				observation = model.Observation{Key: process.Key, FirstObservedAt: now}
				started := time.UnixMilli(process.Key.StartUnixMS)
				if now.Sub(started) <= 5*time.Minute {
					activity := now
					observation.LastActivityAt = &activity
					observation.LastActivityReason = "process started recently"
				}
			}
			if exists && meaningfulCPUAdvance(previous, process, now) {
				activity := now
				observation.LastActivityAt = &activity
				observation.LastActivityReason = "CPU usage increased"
			}
			if process.HasEstablishedConnection() {
				activity := now
				observation.LastActivityAt = &activity
				observation.LastActivityReason = "an established network connection is open"
			}
			observation.PaneID = tree.Attribution.PaneID
			observation.WorkspaceID = tree.Attribution.WorkspaceID
			observation.Agent = tree.Attribution.Agent
			observation.AgentStatus = tree.Attribution.AgentStatus
			observation.CommandSummary = process.CommandSummary
			observation.CommandHash = process.CommandHash
			observation.Executable = process.Executable
			observation.CWD = process.CWD
			observation.PPID = process.PPID
			observation.CPUTimeMillis = process.CPUTimeMillis
			if ports := listeningPorts(process); len(ports) > 0 || len(observation.Ports) == 0 {
				observation.Ports = ports
			}
			observation.LastObservedAt = now
			observation.Count++
			state.Observations[key] = observation
			if observation.FirstObservedAt.Before(first) {
				first = observation.FirstObservedAt
			}
			if observation.Count > count {
				count = observation.Count
			}
			if observation.LastActivityAt != nil && (lastActivity == nil || observation.LastActivityAt.After(*lastActivity)) {
				copy := *observation.LastActivityAt
				lastActivity = &copy
				lastActivityReason = observation.LastActivityReason
			}
		}
		tree.FirstObserved = first
		tree.ObservationCount = count
		tree.LastActivity = lastActivity
		tree.LastActivityReason = lastActivityReason
	}
}

func meaningfulCPUAdvance(previous model.Observation, process model.Process, now time.Time) bool {
	delta := process.CPUTimeMillis - previous.CPUTimeMillis
	if delta <= 0 {
		return false
	}
	elapsed := now.Sub(previous.LastObservedAt).Milliseconds()
	threshold := int64(50)
	if elapsed/100 > threshold { // At least 1% average CPU over the sampling interval.
		threshold = elapsed / 100
	}
	return delta >= threshold
}

func listeningPorts(process model.Process) []string {
	ports := []string{}
	for _, socket := range process.Sockets {
		if socket.Listen {
			ports = append(ports, socket.Local)
		}
	}
	sort.Strings(ports)
	return ports
}

func classifyTrees(trees []model.Tree, state model.PersistedState, now time.Time, config Config) {
	for index := range trees {
		tree := &trees[index]
		tree.Policy = model.PolicyUnreviewed
		root := tree.Process(tree.RootPID)
		if root == nil {
			continue
		}
		if approval, ok := state.Approvals[root.Key.String()]; ok && approvalMatches(approval, tree.Processes) {
			tree.Policy = model.PolicyIntentional
			tree.Evidence = append(tree.Evidence, model.Evidence{Code: "explicit_approval", Message: "This exact live process tree was marked intentional."})
		}
		started := time.UnixMilli(root.Key.StartUnixMS)
		agentWorking := tree.Attribution.AgentStatus == "working" || tree.Attribution.AgentStatus == "blocked"
		hasConnection := false
		for _, process := range tree.Processes {
			hasConnection = hasConnection || process.HasEstablishedConnection()
		}
		recentActivity := tree.LastActivity != nil && now.Sub(*tree.LastActivity) < config.IdleAfter
		recentStart := now.Sub(started) < config.RecentStartAfter
		if agentWorking || hasConnection || recentActivity || recentStart {
			tree.Lifecycle = model.LifecycleActive
			if agentWorking {
				tree.Evidence = append(tree.Evidence, model.Evidence{Code: "agent_active", Message: "The associated agent is currently " + tree.Attribution.AgentStatus + "."})
			}
			if hasConnection {
				tree.Evidence = append(tree.Evidence, model.Evidence{Code: "established_connection", Message: "A process has an established network connection."})
			}
			if recentActivity {
				reason := tree.LastActivityReason
				if reason == "" {
					reason = "CPU or network activity was observed"
				}
				tree.Evidence = append(tree.Evidence, model.Evidence{Code: "recent_activity", Message: reason + " within the idle window."})
			}
			if recentStart {
				tree.Evidence = append(tree.Evidence, model.Evidence{Code: "recent_start", Message: "The process started within the recent-start window."})
			}
		} else {
			tree.Lifecycle = model.LifecycleIdle
			tree.Evidence = append(tree.Evidence, model.Evidence{Code: "idle_threshold", Message: "No activity evidence was observed during the idle window."})
		}
		agentEnded := tree.Attribution.AgentStatus == "done" || tree.Attribution.AgentStatus == "idle" || tree.Attribution.AgentStatus == ""
		observedLongEnough := tree.ObservationCount >= 2 && now.Sub(tree.FirstObserved) >= config.OrphanAfter
		confident := tree.Attribution.Confidence == model.ConfidenceHigh || tree.Attribution.Confidence == model.ConfidenceMedium
		if confident && agentEnded && tree.Policy != model.PolicyIntentional {
			matures := tree.FirstObserved.Add(config.OrphanAfter)
			tree.HistoryMaturesAt = &matures
		}
		if tree.Policy != model.PolicyIntentional && tree.Lifecycle == model.LifecycleIdle && agentEnded && observedLongEnough && confident && !hasConnection {
			tree.Lifecycle = model.LifecycleOrphanCandidate
			tree.Evidence = append(tree.Evidence, model.Evidence{Code: "agent_ended", Message: "The associated agent interval ended while this workload remained alive."})
		}
		if tree.ObservationCount < 2 {
			tree.Evidence = append(tree.Evidence, model.Evidence{Code: "insufficient_history", Message: "At least two observations are required before orphan classification."})
		}
		switch {
		case tree.Policy == model.PolicyIntentional:
			tree.LeftoverAssessment = model.LeftoverIntentional
		case !confident:
			tree.LeftoverAssessment = model.LeftoverUnprovenRelationship
		case agentWorking:
			tree.LeftoverAssessment = model.LeftoverAgentActive
		case tree.Lifecycle == model.LifecycleOrphanCandidate:
			tree.LeftoverAssessment = model.LeftoverLikely
		case tree.Lifecycle == model.LifecycleActive:
			tree.LeftoverAssessment = model.LeftoverRecentActivity
		default:
			tree.LeftoverAssessment = model.LeftoverMonitoring
		}
	}
}

func approvalMatches(approval model.Approval, processes []model.Process) bool {
	actual := map[string]bool{}
	for _, process := range processes {
		actual[process.Key.String()] = true
	}
	if len(actual) != len(approval.Members) {
		return false
	}
	for _, member := range approval.Members {
		if !actual[member.String()] {
			return false
		}
	}
	return true
}

func markDuplicateServices(trees []model.Tree) {
	groups := map[string][]int{}
	for index, tree := range trees {
		root := tree.Process(tree.RootPID)
		if root == nil {
			continue
		}
		hasListener := false
		for _, process := range tree.Processes {
			hasListener = hasListener || process.HasListener()
		}
		if !hasListener {
			continue
		}
		fingerprint := tree.Attribution.WorkspaceID + "\x00" + root.CommandSummary + "\x00" + filepath.Clean(root.CWD)
		groups[fingerprint] = append(groups[fingerprint], index)
	}
	for _, indexes := range groups {
		if len(indexes) < 2 {
			continue
		}
		for _, index := range indexes {
			if trees[index].Policy != model.PolicyIntentional {
				trees[index].Policy = model.PolicySuspicious
			}
			trees[index].Evidence = append(trees[index].Evidence, model.Evidence{Code: "duplicate_service", Message: "Another listening workload with the same project and command summary is running."})
		}
	}
}

func pruneState(state *model.PersistedState, live map[int]model.Process, now time.Time, config Config) {
	cutoff := now.Add(-config.HistoryRetention)
	for key, observation := range state.Observations {
		if observation.LastObservedAt.Before(cutoff) {
			delete(state.Observations, key)
		}
	}
	for key, approval := range state.Approvals {
		root, ok := live[approval.Root.PID]
		if !ok || root.Key != approval.Root {
			delete(state.Approvals, key)
		}
	}
	for key, attempt := range state.TerminationAttempts {
		if attemptExpired(now, attempt.AttemptedAt) {
			delete(state.TerminationAttempts, key)
		}
	}
	if len(state.Observations) > config.MaxObservations {
		items := make([]model.Observation, 0, len(state.Observations))
		for _, item := range state.Observations {
			items = append(items, item)
		}
		sort.Slice(items, func(i, j int) bool { return items[i].LastObservedAt.Before(items[j].LastObservedAt) })
		for _, item := range items[:len(items)-config.MaxObservations] {
			delete(state.Observations, item.Key.String())
		}
	}
	intervalCutoff := now.Add(-config.HistoryRetention)
	kept := state.AgentIntervals[:0]
	for _, interval := range state.AgentIntervals {
		if interval.EndedAt == nil || interval.EndedAt.After(intervalCutoff) {
			kept = append(kept, interval)
		}
	}
	state.AgentIntervals = kept
}

func summarize(trees []model.Tree) model.Summary {
	summary := model.Summary{Trees: len(trees)}
	for _, tree := range trees {
		summary.Processes += len(tree.Processes)
		switch tree.Lifecycle {
		case model.LifecycleActive:
			summary.Active++
		case model.LifecycleIdle:
			summary.Idle++
		case model.LifecycleOrphanCandidate:
			summary.OrphanCandidates++
		}
		switch tree.Policy {
		case model.PolicySuspicious:
			summary.Suspicious++
		case model.PolicyIntentional:
			summary.Intentional++
		}
	}
	return summary
}

func (e *Engine) FindTree(report model.Report, pid int) (*model.Tree, error) {
	for index := range report.Trees {
		if report.Trees[index].Process(pid) != nil {
			return &report.Trees[index], nil
		}
	}
	return nil, fmt.Errorf("process %d is not an attributed workload in a Herdr pane", pid)
}

func (e *Engine) MarkIntentional(pid int) (model.Tree, error) {
	report, err := e.Scan("mark-intentional")
	if err != nil {
		return model.Tree{}, err
	}
	tree, err := e.FindTree(report, pid)
	if err != nil {
		return model.Tree{}, err
	}
	root := tree.Process(tree.RootPID)
	if root == nil {
		return model.Tree{}, errors.New("workload root disappeared")
	}
	members := make([]model.ProcessKey, 0, len(tree.Processes))
	for _, process := range tree.Processes {
		members = append(members, process.Key)
	}
	_, err = e.Store.Update(func(state *model.PersistedState) error {
		state.Approvals[root.Key.String()] = model.Approval{Root: root.Key, Members: members, MarkedAt: e.Now().UTC()}
		return nil
	})
	return *tree, err
}

func (e *Engine) UnmarkIntentional(pid int) error {
	removed := false
	_, err := e.Store.Update(func(current *model.PersistedState) error {
		for key, approval := range current.Approvals {
			if approval.Root.PID == pid {
				delete(current.Approvals, key)
				removed = true
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	if !removed {
		return fmt.Errorf("process %d is not marked intentional", pid)
	}
	return nil
}
