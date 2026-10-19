package model

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

const SchemaVersion = 1

type Lifecycle string

const (
	LifecycleActive          Lifecycle = "active"
	LifecycleIdle            Lifecycle = "idle"
	LifecycleOrphanCandidate Lifecycle = "orphan_candidate"
	LifecycleExited          Lifecycle = "exited"
)

type Policy string

const (
	PolicyIntentional Policy = "intentional"
	PolicyUnreviewed  Policy = "unreviewed"
	PolicySuspicious  Policy = "suspicious"
)

type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

type Relationship string

const (
	RelationshipCurrentAgentAncestry Relationship = "current_agent_ancestry"
	RelationshipRecordedAgentWindow  Relationship = "recorded_agent_window"
	RelationshipSharedPaneSession    Relationship = "shared_pane_session"
	RelationshipUnproven             Relationship = "unproven"
)

type LeftoverAssessment string

const (
	LeftoverLikely               LeftoverAssessment = "likely_leftover"
	LeftoverIntentional          LeftoverAssessment = "intentional"
	LeftoverAgentActive          LeftoverAssessment = "agent_active"
	LeftoverRecentActivity       LeftoverAssessment = "recent_process_activity"
	LeftoverMonitoring           LeftoverAssessment = "monitoring"
	LeftoverUnprovenRelationship LeftoverAssessment = "unproven_relationship"
)

type ProcessKey struct {
	PID         int    `json:"pid"`
	BootID      string `json:"boot_id,omitempty"`
	StartTicks  uint64 `json:"start_ticks,omitempty"`
	StartUnixMS int64  `json:"start_unix_ms"`
}

func (k ProcessKey) String() string {
	if k.BootID != "" {
		return fmt.Sprintf("%d:%s:%d", k.PID, k.BootID, k.StartTicks)
	}
	return fmt.Sprintf("%d:%d", k.PID, k.StartUnixMS)
}

type Socket struct {
	Protocol string `json:"protocol"`
	Local    string `json:"local,omitempty"`
	State    string `json:"state,omitempty"`
	Listen   bool   `json:"listen,omitempty"`
}

type Process struct {
	Key              ProcessKey `json:"key"`
	PPID             int        `json:"ppid"`
	PGID             int        `json:"pgid"`
	SessionID        int        `json:"session_id"`
	UID              int        `json:"uid"`
	Name             string     `json:"name"`
	Executable       string     `json:"executable,omitempty"`
	ExecutableDevice uint64     `json:"executable_device,omitempty"`
	ExecutableInode  uint64     `json:"executable_inode,omitempty"`
	Command          string     `json:"command,omitempty"`
	CommandSummary   string     `json:"command_summary"`
	CommandHash      string     `json:"command_hash"`
	CWD              string     `json:"cwd,omitempty"`
	State            string     `json:"state,omitempty"`
	RSSBytes         uint64     `json:"rss_bytes,omitempty"`
	CPUTimeMillis    int64      `json:"cpu_time_ms,omitempty"`
	// Linux cumulative disk and syscall I/O counters. Chars include cached and pipe I/O.
	IOReadBytes  uint64 `json:"io_read_bytes,omitempty"`
	IOWriteBytes uint64 `json:"io_write_bytes,omitempty"`
	IOReadChars  uint64 `json:"io_read_chars,omitempty"`
	IOWriteChars uint64 `json:"io_write_chars,omitempty"`
	// Automatic cleanup requires these flags for each target and a complete ancestry graph.
	TelemetryComplete bool        `json:"telemetry_complete"`
	ChildrenComplete  bool        `json:"children_complete"`
	SocketsComplete   bool        `json:"sockets_complete"`
	IOComplete        bool        `json:"io_complete"`
	Sockets           []Socket    `json:"sockets,omitempty"`
	Children          []int       `json:"children,omitempty"`
	RecordedParent    *ProcessKey `json:"recorded_parent,omitempty"`
	Detached          bool        `json:"detached,omitempty"`
	RecordedListener  bool        `json:"recorded_listener,omitempty"`
	Infrastructure    bool        `json:"infrastructure,omitempty"`
	Protected         bool        `json:"protected,omitempty"`
	ProtectionReason  string      `json:"protection_reason,omitempty"`
}

func (p Process) HasListener() bool {
	for _, socket := range p.Sockets {
		if socket.Listen {
			return true
		}
	}
	return false
}

func (p Process) HasEstablishedConnection() bool {
	for _, socket := range p.Sockets {
		if strings.EqualFold(socket.State, "ESTABLISHED") {
			return true
		}
	}
	return false
}

type AgentSession struct {
	Source string `json:"source,omitempty"`
	Agent  string `json:"agent,omitempty"`
	Kind   string `json:"kind,omitempty"`
	Value  string `json:"value,omitempty"`
}

type LineageProcess struct {
	PID  int    `json:"pid"`
	Name string `json:"name"`
	Role string `json:"role"`
}

type Attribution struct {
	WorkspaceID   string           `json:"workspace_id"`
	WorkspaceName string           `json:"workspace_name,omitempty"`
	WorkspaceCWD  string           `json:"workspace_cwd,omitempty"`
	PaneID        string           `json:"pane_id"`
	TabID         string           `json:"tab_id,omitempty"`
	TabLabel      string           `json:"tab_label,omitempty"`
	PaneLabel     string           `json:"pane_label,omitempty"`
	PaneTitle     string           `json:"pane_title,omitempty"`
	PaneCWD       string           `json:"pane_cwd,omitempty"`
	Agent         string           `json:"agent,omitempty"`
	AgentStatus   string           `json:"agent_status,omitempty"`
	AgentSession  *AgentSession    `json:"agent_session,omitempty"`
	Confidence    Confidence       `json:"confidence"`
	Method        string           `json:"method"`
	Relationship  Relationship     `json:"relationship"`
	ShellPID      int              `json:"shell_pid,omitempty"`
	AgentPID      int              `json:"agent_pid,omitempty"`
	Lineage       []LineageProcess `json:"lineage,omitempty"`
}

type Evidence struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type Tree struct {
	RootPID            int                `json:"root_pid"`
	Processes          []Process          `json:"processes"`
	Attribution        Attribution        `json:"attribution"`
	Lifecycle          Lifecycle          `json:"lifecycle"`
	Policy             Policy             `json:"policy"`
	Evidence           []Evidence         `json:"evidence"`
	LastActivity       *time.Time         `json:"last_activity_at,omitempty"`
	LastActivityReason string             `json:"last_activity_reason,omitempty"`
	FirstObserved      time.Time          `json:"first_observed_at"`
	ObservationCount   int                `json:"observation_count"`
	LeftoverAssessment LeftoverAssessment `json:"leftover_assessment"`
	HistoryMaturesAt   *time.Time         `json:"history_matures_at,omitempty"`
}

func (t Tree) Process(pid int) *Process {
	for index := range t.Processes {
		if t.Processes[index].Key.PID == pid {
			return &t.Processes[index]
		}
	}
	return nil
}

func (t Tree) SortedProcesses() []Process {
	result := append([]Process(nil), t.Processes...)
	sort.Slice(result, func(i, j int) bool { return result[i].Key.PID < result[j].Key.PID })
	return result
}

type Summary struct {
	Trees            int `json:"trees"`
	Processes        int `json:"processes"`
	Active           int `json:"active"`
	Idle             int `json:"idle"`
	OrphanCandidates int `json:"orphan_candidates"`
	Suspicious       int `json:"suspicious"`
	Intentional      int `json:"intentional"`
}

type Report struct {
	SchemaVersion int       `json:"schema_version"`
	ObservedAt    time.Time `json:"observed_at"`
	Summary       Summary   `json:"summary"`
	Trees         []Tree    `json:"trees"`
	Warnings      []string  `json:"warnings,omitempty"`
}

type Approval struct {
	Root     ProcessKey   `json:"root"`
	Members  []ProcessKey `json:"members"`
	MarkedAt time.Time    `json:"marked_at"`
}

type Observation struct {
	Key                ProcessKey `json:"key"`
	PaneID             string     `json:"pane_id"`
	WorkspaceID        string     `json:"workspace_id"`
	Agent              string     `json:"agent,omitempty"`
	AgentStatus        string     `json:"agent_status,omitempty"`
	CommandSummary     string     `json:"command_summary"`
	CommandHash        string     `json:"command_hash"`
	Executable         string     `json:"executable,omitempty"`
	CWD                string     `json:"cwd,omitempty"`
	Ports              []string   `json:"ports,omitempty"`
	PPID               int        `json:"ppid"`
	CPUTimeMillis      int64      `json:"cpu_time_ms"`
	FirstObservedAt    time.Time  `json:"first_observed_at"`
	LastObservedAt     time.Time  `json:"last_observed_at"`
	LastActivityAt     *time.Time `json:"last_activity_at,omitempty"`
	LastActivityReason string     `json:"last_activity_reason,omitempty"`
	Count              int        `json:"count"`
}

type AgentInterval struct {
	PaneID    string     `json:"pane_id"`
	Agent     string     `json:"agent"`
	Session   string     `json:"session,omitempty"`
	StartedAt time.Time  `json:"started_at"`
	EndedAt   *time.Time `json:"ended_at,omitempty"`
}

type PersistedState struct {
	SchemaVersion       int                           `json:"schema_version"`
	Observations        map[string]Observation        `json:"observations"`
	Approvals           map[string]Approval           `json:"approvals"`
	TerminationAttempts map[string]TerminationAttempt `json:"termination_attempts,omitempty"`
	AgentIntervals      []AgentInterval               `json:"agent_intervals"`
	UpdatedAt           time.Time                     `json:"updated_at"`
}

type TerminationAttempt struct {
	Selected    ProcessKey        `json:"selected"`
	Survivors   []ProcessIdentity `json:"survivors"`
	AttemptedAt time.Time         `json:"attempted_at"`
}

type ProcessIdentity struct {
	Key         ProcessKey `json:"key"`
	SessionID   int        `json:"session_id"`
	Executable  string     `json:"executable,omitempty"`
	CommandHash string     `json:"command_hash"`
}

func NewState() PersistedState {
	return PersistedState{SchemaVersion: SchemaVersion, Observations: map[string]Observation{}, Approvals: map[string]Approval{}, TerminationAttempts: map[string]TerminationAttempt{}}
}

func HashCommand(command string) string {
	digest := sha256.Sum256([]byte(command))
	return hex.EncodeToString(digest[:])
}
