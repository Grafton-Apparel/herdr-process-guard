package store

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Efeguclu1/herdr-process-guard/internal/model"
)

func TestConcurrentUpdatesAreSerializedAndStateIsPrivate(t *testing.T) {
	directory := t.TempDir()
	storage := New(directory)
	var group sync.WaitGroup
	for index := 0; index < 12; index++ {
		index := index
		group.Add(1)
		go func() {
			defer group.Done()
			_, err := storage.Update(func(state *model.PersistedState) error {
				key := model.ProcessKey{PID: index + 10, StartUnixMS: 1000}.String()
				state.Observations[key] = model.Observation{Key: model.ProcessKey{PID: index + 10, StartUnixMS: 1000}, CommandSummary: "node", CommandHash: fmt.Sprint(index), FirstObservedAt: time.Now(), LastObservedAt: time.Now()}
				return nil
			})
			if err != nil {
				t.Errorf("update: %v", err)
			}
		}()
	}
	group.Wait()
	state, err := storage.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Observations) != 12 {
		t.Fatalf("lost concurrent updates: %d", len(state.Observations))
	}
	bytes, err := os.ReadFile(storage.statePath())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(bytes), "raw-secret") {
		t.Fatal("raw secret persisted")
	}
}

func TestRejectsUnknownSchema(t *testing.T) {
	storage := New(t.TempDir())
	if err := os.WriteFile(storage.statePath(), []byte(`{"schema_version":99,"observations":{},"approvals":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Load(); err == nil {
		t.Fatal("expected unsupported schema error")
	}
}

func TestSessionDirectoryIsSharedAndSocketScoped(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HERDR_PLUGIN_STATE_DIR", root)
	a, err := SessionDirectory("/tmp/herdr-a.sock")
	if err != nil {
		t.Fatal(err)
	}
	b, err := SessionDirectory("/tmp/herdr-b.sock")
	if err != nil {
		t.Fatal(err)
	}
	again, err := SessionDirectory("/tmp/./herdr-a.sock")
	if err != nil {
		t.Fatal(err)
	}
	if a == b || a != again || !strings.HasPrefix(a, root+"/") {
		t.Fatalf("namespace %q %q %q", a, b, again)
	}
}

func TestDefaultDirectoryMatchesHerdr095StateNamespace(t *testing.T) {
	t.Setenv("HERDR_PLUGIN_STATE_DIR", "")
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	want := filepath.Join(os.Getenv("XDG_STATE_HOME"), "herdr", "plugins", "herdr.process-guard")
	got, err := DefaultDirectory()
	if err != nil || got != want {
		t.Fatalf("XDG state root: %q want %q (%v)", got, want, err)
	}
	t.Setenv("HERDR_PLUGIN_STATE_DIR", want)
	plugin, err := DefaultDirectory()
	if err != nil || plugin != got {
		t.Fatal("plugin and service namespace differs", plugin, got, err)
	}
	t.Setenv("HERDR_PLUGIN_STATE_DIR", "")
	t.Setenv("XDG_STATE_HOME", "")
	t.Setenv("HOME", t.TempDir())
	want = filepath.Join(os.Getenv("HOME"), ".local", "state", "herdr", "plugins", "herdr.process-guard")
	got, err = DefaultDirectory()
	if err != nil || got != want {
		t.Fatalf("HOME state root: %q want %q (%v)", got, want, err)
	}
	override := t.TempDir()
	t.Setenv("HERDR_PLUGIN_STATE_DIR", override)
	got, err = DefaultDirectory()
	if err != nil || got != override {
		t.Fatal("explicit plugin override ignored", got, err)
	}
}
