package main

import (
	"github.com/Efeguclu1/herdr-process-guard/internal/watchdog"
	"os"
	"path/filepath"
	"testing"
)

func TestStandaloneCommandsDoNotNeedHerdrSocket(t *testing.T) {
	t.Setenv("HERDR_SOCKET_PATH", "")
	d := t.TempDir()
	t.Setenv("HERDR_PLUGIN_STATE_DIR", d)
	for _, command := range []string{"watchdog-config", "watchdog-status", "watchdog-report", "pause", "resume"} {
		if err := run([]string{command}); err != nil {
			t.Fatalf("%s: %v", command, err)
		}
	}
	repo := watchdog.Repository{Directory: d}
	st, err := repo.Load()
	if err != nil || st.Paused {
		t.Fatal(st, err)
	}
	if _, err = os.Stat(filepath.Join(d, "watchdog.json")); err != nil {
		t.Fatal(err)
	}
}
