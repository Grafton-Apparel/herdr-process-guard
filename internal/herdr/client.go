package herdr

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"sync/atomic"
	"time"

	"github.com/Efeguclu1/herdr-process-guard/internal/model"
)

type Client struct {
	SocketPath string
	Context    context.Context
	Timeout    time.Duration
	sequence   atomic.Uint64
	Dial       func() (net.Conn, error)
}

type Snapshot struct {
	Version            string      `json:"version"`
	Protocol           int         `json:"protocol"`
	FocusedWorkspaceID string      `json:"focused_workspace_id,omitempty"`
	FocusedTabID       string      `json:"focused_tab_id,omitempty"`
	FocusedPaneID      string      `json:"focused_pane_id,omitempty"`
	Workspaces         []Workspace `json:"workspaces"`
	Tabs               []Tab       `json:"tabs"`
	Panes              []Pane      `json:"panes"`
	Agents             []Agent     `json:"agents"`
}

type Workspace struct {
	WorkspaceID string    `json:"workspace_id"`
	Label       string    `json:"label"`
	Number      int       `json:"number,omitempty"`
	AgentStatus string    `json:"agent_status"`
	Worktree    *Worktree `json:"worktree,omitempty"`
}

type Tab struct {
	TabID       string `json:"tab_id"`
	WorkspaceID string `json:"workspace_id"`
	Label       string `json:"label,omitempty"`
	Number      int    `json:"number,omitempty"`
}

type Worktree struct {
	RepoName     string `json:"repo_name"`
	RepoRoot     string `json:"repo_root"`
	CheckoutPath string `json:"checkout_path"`
}

type Pane struct {
	PaneID        string              `json:"pane_id"`
	TerminalID    string              `json:"terminal_id"`
	WorkspaceID   string              `json:"workspace_id"`
	TabID         string              `json:"tab_id"`
	Label         string              `json:"label,omitempty"`
	TerminalTitle string              `json:"terminal_title_stripped,omitempty"`
	CWD           string              `json:"cwd,omitempty"`
	ForegroundCWD string              `json:"foreground_cwd,omitempty"`
	Agent         string              `json:"agent,omitempty"`
	DisplayAgent  string              `json:"display_agent,omitempty"`
	AgentStatus   string              `json:"agent_status"`
	AgentSession  *model.AgentSession `json:"agent_session,omitempty"`
}

type Agent struct {
	PaneID       string              `json:"pane_id"`
	WorkspaceID  string              `json:"workspace_id"`
	Agent        string              `json:"agent,omitempty"`
	DisplayAgent string              `json:"display_agent,omitempty"`
	AgentStatus  string              `json:"agent_status"`
	AgentSession *model.AgentSession `json:"agent_session,omitempty"`
}

type ProcessInfo struct {
	PaneID                   string              `json:"pane_id"`
	ShellPID                 *int                `json:"shell_pid,omitempty"`
	ForegroundProcessGroupID *int                `json:"foreground_process_group_id,omitempty"`
	ForegroundProcesses      []ForegroundProcess `json:"foreground_processes"`
}

type ForegroundProcess struct {
	PID     int      `json:"pid"`
	Name    string   `json:"name"`
	Argv0   string   `json:"argv0,omitempty"`
	Argv    []string `json:"argv,omitempty"`
	Cmdline string   `json:"cmdline,omitempty"`
	CWD     string   `json:"cwd,omitempty"`
}

type wireResponse struct {
	ID     string          `json:"id"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *wireError      `json:"error,omitempty"`
}

type wireError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func NewFromEnvironment() (*Client, error) {
	path := os.Getenv("HERDR_SOCKET_PATH")
	if path == "" {
		return nil, errors.New("HERDR_SOCKET_PATH is not set; run inside Herdr or export the active Herdr socket path")
	}
	return &Client{SocketPath: path}, nil
}

func (c *Client) call(method string, params any, destination any) error {
	id := fmt.Sprintf("process-guard:%d", c.sequence.Add(1))
	request := map[string]any{"id": id, "method": method, "params": params}
	var connection net.Conn
	var err error
	if c.Dial != nil {
		connection, err = c.Dial()
	} else {
		ctx := c.Context
		if ctx == nil {
			ctx = context.Background()
		}
		dialer := net.Dialer{Timeout: 2 * time.Second}
		connection, err = dialer.DialContext(ctx, "unix", c.SocketPath)
	}
	if err != nil {
		return fmt.Errorf("connect to Herdr: %w", err)
	}
	defer connection.Close()
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	deadline := time.Now().Add(timeout)
	if c.Context != nil {
		if d, ok := c.Context.Deadline(); ok && d.Before(deadline) {
			deadline = d
		}
	}
	if err := connection.SetDeadline(deadline); err != nil {
		return fmt.Errorf("set Herdr request deadline: %w", err)
	}
	if err := json.NewEncoder(connection).Encode(request); err != nil {
		return fmt.Errorf("send Herdr request: %w", err)
	}
	var response wireResponse
	if err := json.NewDecoder(bufio.NewReader(connection)).Decode(&response); err != nil {
		return fmt.Errorf("read Herdr response: %w", err)
	}
	if response.Error != nil {
		return fmt.Errorf("Herdr %s: %s", response.Error.Code, response.Error.Message)
	}
	if destination == nil {
		return nil
	}
	if err := json.Unmarshal(response.Result, destination); err != nil {
		return fmt.Errorf("decode Herdr %s response: %w", method, err)
	}
	return nil
}

func (c *Client) SessionSnapshot() (Snapshot, error) {
	var result struct {
		Type     string   `json:"type"`
		Snapshot Snapshot `json:"snapshot"`
	}
	if err := c.call("session.snapshot", map[string]any{}, &result); err != nil {
		return Snapshot{}, err
	}
	return result.Snapshot, nil
}

func (c *Client) PaneProcessInfo(paneID string) (ProcessInfo, error) {
	var result struct {
		Type        string      `json:"type"`
		ProcessInfo ProcessInfo `json:"process_info"`
	}
	if err := c.call("pane.process_info", map[string]any{"pane_id": paneID}, &result); err != nil {
		return ProcessInfo{}, err
	}
	return result.ProcessInfo, nil
}

func (c *Client) Notify(title, body string) error {
	return c.call("notification.show", map[string]any{"title": title, "body": body, "sound": "none"}, nil)
}
func (c *Client) OpenDashboard(entrypoint string) error {
	return c.call("plugin.pane.open", map[string]any{"plugin_id": "herdr.process-guard", "entrypoint": entrypoint, "placement": "popup"}, nil)
}
