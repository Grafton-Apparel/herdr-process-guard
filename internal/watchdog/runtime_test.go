package watchdog

import (
	"context"
	"errors"
	"github.com/Efeguclu1/herdr-process-guard/internal/model"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStrictConfig(t *testing.T) {
	for _, body := range []string{`{"typo":1}`, `{"cleanup":true,"orphan_seconds":2}`, `{} {}`, `{"poll_seconds":0}`} {
		p := filepath.Join(t.TempDir(), "config.json")
		_ = os.WriteFile(p, []byte(body), 0600)
		if _, err := LoadConfig(p); err == nil {
			t.Fatalf("accepted %s", body)
		}
	}
}
func TestDurableStatePauseAndExclusiveLock(t *testing.T) {
	d := t.TempDir()
	repo := Repository{Directory: d}
	s := NewState()
	s.Paused = true
	if err := repo.Save(s); err != nil {
		t.Fatal(err)
	}
	s, err := repo.Load()
	if err != nil || !s.Paused {
		t.Fatal(s, err)
	}
	if err = repo.Pause(false); err != nil {
		t.Fatal(err)
	}
	s, _ = repo.Load()
	if s.Paused {
		t.Fatal("resume not persisted")
	}
	l, err := Acquire(d)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Acquire(d); err == nil {
		t.Fatal("duplicate watcher allowed")
	}
	_ = l.Close()
	l, err = Acquire(d)
	if err != nil {
		t.Fatal(err)
	}
	_ = l.Close()
}

type fakePin struct {
	revalidateErr error
	signals       *int
	closed        *int
}

func (p *fakePin) Revalidate() error { return p.revalidateErr }
func (p *fakePin) SIGTERM() error    { *p.signals++; return nil }
func (p *fakePin) Close() error      { *p.closed++; return nil }
func TestCleanupFreshSnapshotsPinsIntentionalAndAttempts(t *testing.T) {
	for _, failure := range []string{"none", "fresh-session-gap", "new-child", "marked", "pin", "revalidate", "pause", "activity"} {
		t.Run(failure, func(t *testing.T) {
			st, s, now := observeMature(t, nil, false)
			now = now.Add(Defaults().Poll())
			cfg := Defaults()
			cfg.Cleanup = true
			calls, signals, closed := 0, 0, 0
			r := Runner{Config: cfg, Repo: Repository{Directory: t.TempDir()}, Now: func() time.Time { return now }, Source: func() (Snapshot, error) {
				calls++
				fresh := s
				if calls > 1 {
					switch failure {
					case "fresh-session-gap":
						fresh.Complete = false
					case "new-child":
						fresh.Processes = map[int]model.Process{}
						for k, p := range s.Processes {
							fresh.Processes[k] = p
						}
						p := fresh.Processes[30]
						p.Children = []int{999}
						fresh.Processes[30] = p
					case "marked":
						fresh.Intentional = map[string]bool{s.Processes[30].Key.String(): true}
					case "activity":
						fresh.Processes = map[int]model.Process{}
						for k, p := range s.Processes {
							fresh.Processes[k] = p
						}
						p := fresh.Processes[30]
						p.IOReadBytes++
						fresh.Processes[30] = p
					}
				}
				return fresh, nil
			}, Pin: func(p model.Process) (Pin, error) {
				if failure == "pin" {
					return nil, errors.New("pin failed")
				}
				x := &fakePin{signals: &signals, closed: &closed}
				if failure == "revalidate" {
					x.revalidateErr = errors.New("changed")
				}
				return x, nil
			}, Sleep: func(time.Duration) {}}
			if failure == "pause" {
				st.Paused = true
			}
			if err := r.Repo.Save(st); err != nil {
				t.Fatal(err)
			}
			if err := r.Once(&st); err != nil {
				t.Fatal(err)
			}
			want := 0
			if failure == "none" {
				want = 1
			}
			if signals != want {
				t.Fatalf("signals %d want %d", signals, want)
			}
			if failure == "none" {
				if calls < 3 {
					t.Fatal("missing final tree scan")
				}
				if !st.Records[s.Processes[30].Key.String()].Attempted {
					t.Fatal("attempt not durable")
				}
				if err := r.Once(&st); err != nil {
					t.Fatal(err)
				}
				if signals != 1 {
					t.Fatal("repeated termination")
				}
				if closed != 1 {
					t.Fatal("pin leaked")
				}
			}
		})
	}
}
func TestDiscoveryExactLocalSocketsAndStoppedSessions(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HERDR_CONFIG_PATH", root)
	t.Setenv("HERDR_SOCKET_PATH", "")
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	_ = os.MkdirAll(filepath.Join(root, "sessions", "saved"), 0700)
	_ = os.WriteFile(filepath.Join(root, "sessions", "saved", "session.json"), []byte("{}"), 0600)
	_ = os.WriteFile(filepath.Join(root, "herdr-client.sock"), nil, 0600)
	paths, saved, err := Discover()
	if err != nil || len(paths) != 0 || len(saved) != 1 {
		t.Fatal(paths, saved, err)
	}
	_ = os.MkdirAll(filepath.Join(root, "sessions", "named"), 0700)
	_ = os.WriteFile(filepath.Join(root, "sessions", "named", "herdr.sock"), nil, 0600)
	_ = os.WriteFile(filepath.Join(root, "herdr.sock"), nil, 0600)
	t.Setenv("HERDR_SOCKET_PATH", filepath.Join(root, ".", "herdr.sock"))
	paths, _, err = Discover()
	if err != nil || len(paths) != 2 {
		t.Fatal(paths, err)
	}
}
func TestRuntimeEventsDeduplicateAndPersistDeliveryCooldown(t *testing.T) {
	repo := Repository{Directory: t.TempDir()}
	now := time.Unix(10000, 0)
	calls := 0
	r := Runner{Config: Defaults(), Repo: repo, Now: func() time.Time { return now }, Notify: func(Event) error { calls++; return nil }}
	for i := 0; i < 2; i++ {
		if err := r.event(Event{Kind: "cleanup-blocked", Key: "root-30", Summary: "test"}); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 {
		t.Fatal("duplicate runtime notification", calls)
	}
	st := NewState()
	if err := repo.Save(st); err != nil {
		t.Fatal(err)
	}
	if err := r.event(Event{Kind: "cleanup-blocked", Key: "root-30", Summary: "test"}); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatal("state save lost cooldown")
	}
	now = now.Add(Defaults().Cooldown())
	if err := r.event(Event{Kind: "cleanup-blocked", Key: "root-30", Summary: "test"}); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatal("cooldown never expired")
	}
}
func TestShutdownBeforeSignalCancelsCleanup(t *testing.T) {
	st, s, now := observeMature(t, nil, false)
	now = now.Add(Defaults().Poll())
	ctx, cancel := context.WithCancel(context.Background())
	cfg := Defaults()
	cfg.Cleanup = true
	signals, closed, calls := 0, 0, 0
	r := Runner{Config: cfg, Repo: Repository{Directory: t.TempDir()}, Context: ctx, Now: func() time.Time { return now }, Source: func() (Snapshot, error) {
		calls++
		if calls == 4 {
			cancel()
		}
		return s, nil
	}, Pin: func(model.Process) (Pin, error) { return &fakePin{signals: &signals, closed: &closed}, nil }}
	if err := r.Repo.Save(st); err != nil {
		t.Fatal(err)
	}
	_ = r.Once(&st)
	if signals != 0 || closed != 1 {
		t.Fatal("shutdown allowed signal or leaked pin", signals, closed)
	}
}
func TestAttemptWriteFailurePreventsSignal(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission fixture requires unprivileged user")
	}
	st, s, now := observeMature(t, nil, false)
	now = now.Add(Defaults().Poll())
	cfg := Defaults()
	cfg.Cleanup = true
	dir := t.TempDir()
	repo := Repository{Directory: dir}
	signals, closed, calls := 0, 0, 0
	r := Runner{Config: cfg, Repo: repo, Now: func() time.Time { return now }, Source: func() (Snapshot, error) {
		calls++
		if calls == 3 {
			if err := os.Chmod(dir, 0500); err != nil {
				t.Fatal(err)
			}
		}
		return s, nil
	}, Pin: func(model.Process) (Pin, error) { return &fakePin{signals: &signals, closed: &closed}, nil }}
	t.Cleanup(func() { _ = os.Chmod(dir, 0700) })
	if err := repo.Save(st); err != nil {
		t.Fatal(err)
	}
	if err := r.Once(&st); err == nil {
		t.Fatal("write failure ignored")
	}
	if signals != 0 || closed != 1 {
		t.Fatal("signal after failed state write or pin leak", signals, closed)
	}
	_ = os.Chmod(dir, 0700)
	saved, err := repo.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(saved.Attempts) != 0 {
		t.Fatal("uncommitted attempt reached disk")
	}
}
