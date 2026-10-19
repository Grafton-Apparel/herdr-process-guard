package herdr

import (
	"bufio"
	"encoding/json"
	"net"
	"testing"
)

func TestClientReadsSnapshotAndProcessInfo(t *testing.T) {
	responses := map[string]any{
		"session.snapshot": map[string]any{"type": "session_snapshot", "snapshot": map[string]any{
			"version": "0.8.0", "protocol": 1,
			"workspaces": []any{map[string]any{"workspace_id": "w1", "label": "demo", "agent_status": "idle"}},
			"tabs":       []any{map[string]any{"tab_id": "w1:t1", "workspace_id": "w1", "label": "API work", "number": 1}},
			"panes":      []any{map[string]any{"pane_id": "w1:p1", "tab_id": "w1:t1", "terminal_title_stripped": "Server", "foreground_cwd": "/repo"}},
			"agents":     []any{},
		}},
		"pane.process_info": map[string]any{"type": "pane_process_info", "process_info": map[string]any{"pane_id": "w1:p1", "shell_pid": 42, "foreground_processes": []any{}}},
	}
	done := make(chan struct{}, 2)
	client := &Client{Dial: func() (net.Conn, error) {
		clientSide, serverSide := net.Pipe()
		go func(connection net.Conn) {
			defer func() { done <- struct{}{} }()
			var request map[string]any
			_ = json.NewDecoder(bufio.NewReader(connection)).Decode(&request)
			_ = json.NewEncoder(connection).Encode(map[string]any{"id": request["id"], "result": responses[request["method"].(string)]})
			_ = connection.Close()
		}(serverSide)
		return clientSide, nil
	}}
	snapshot, err := client.SessionSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Version != "0.8.0" || snapshot.Workspaces[0].Label != "demo" {
		t.Fatalf("unexpected snapshot: %+v", snapshot)
	}
	if snapshot.Tabs[0].Label != "API work" || snapshot.Panes[0].TerminalTitle != "Server" || snapshot.Panes[0].ForegroundCWD != "/repo" {
		t.Fatalf("human pane metadata was not decoded: %+v", snapshot)
	}
	info, err := client.PaneProcessInfo("w1:p1")
	if err != nil {
		t.Fatal(err)
	}
	if info.ShellPID == nil || *info.ShellPID != 42 {
		t.Fatalf("unexpected process info: %+v", info)
	}
	<-done
	<-done
}

func TestNotificationWireMethodAndSilentSound(t *testing.T) {
	done := make(chan map[string]any, 1)
	c := &Client{Dial: func() (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			var req map[string]any
			_ = json.NewDecoder(server).Decode(&req)
			done <- req
			_ = json.NewEncoder(server).Encode(map[string]any{"id": req["id"], "result": map[string]any{}})
		}()
		return client, nil
	}}
	if err := c.Notify("title", "body"); err != nil {
		t.Fatal(err)
	}
	r := <-done
	p := r["params"].(map[string]any)
	if r["method"] != "notification.show" || p["title"] != "title" || p["body"] != "body" || p["sound"] != "none" {
		t.Fatalf("wrong RPC: %+v", r)
	}
}
func TestOpenDashboardUsesPluginPane(t *testing.T) {
	done := make(chan map[string]any, 1)
	c := &Client{Dial: func() (net.Conn, error) {
		a, b := net.Pipe()
		go func() {
			defer b.Close()
			var req map[string]any
			_ = json.NewDecoder(b).Decode(&req)
			done <- req
			_ = json.NewEncoder(b).Encode(map[string]any{"id": req["id"], "result": map[string]any{}})
		}()
		return a, nil
	}}
	if err := c.OpenDashboard("watchdog-status"); err != nil {
		t.Fatal(err)
	}
	r := <-done
	p := r["params"].(map[string]any)
	if r["method"] != "plugin.pane.open" || p["entrypoint"] != "watchdog-status" || p["placement"] != "popup" || p["plugin_id"] != "herdr.process-guard" {
		t.Fatal(r)
	}
}
