package watchdog

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

type Repository struct{ Directory string }

func (r Repository) path() string { return filepath.Join(r.Directory, "watchdog.json") }
func (r Repository) locked(fn func() error) error {
	if err := os.MkdirAll(r.Directory, 0700); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(r.Directory, ".watchdog-state.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	return fn()
}
func (r Repository) load() (State, error) {
	f, err := os.Open(r.path())
	if os.IsNotExist(err) {
		return NewState(), nil
	}
	if err != nil {
		return State{}, err
	}
	defer f.Close()
	s := NewState()
	d := json.NewDecoder(io.LimitReader(f, 64<<20))
	if err = d.Decode(&s); err != nil {
		return s, err
	}
	if s.Attempts == nil || s.Records == nil || s.Cooldowns == nil || s.Resources == nil || s.Idle == nil {
		return s, fmt.Errorf("invalid watchdog state")
	}
	return s, nil
}
func (r Repository) Load() (s State, err error) {
	err = r.locked(func() error { s, err = r.load(); return err })
	return
}
func (r Repository) write(s State) error {
	// Persist identity/activity evidence, never raw command arguments or working paths.
	clone := s
	clone.Records = map[string]Record{}
	for k, v := range s.Records {
		v.Last.Command = ""
		v.Last.CWD = ""
		v.Last.Sockets = nil
		v.Last.CommandSummary = SafeText(v.Last.CommandSummary)
		clone.Records[k] = v
	}
	clone.Resources = map[string]Resource{}
	for k, v := range s.Resources {
		v.Last.Command = ""
		v.Last.CWD = ""
		v.Last.Sockets = nil
		clone.Resources[k] = v
	}
	f, err := os.CreateTemp(r.Directory, ".watchdog-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if err = f.Chmod(0600); err != nil {
		return err
	}
	if err = json.NewEncoder(f).Encode(clone); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(f.Name(), r.path()); err != nil {
		return err
	}
	dir, err := os.Open(r.Directory)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
func (r Repository) Save(s State) error {
	return r.locked(func() error {
		if _, err := os.Stat(r.path()); err == nil {
			current, err := r.load()
			if err != nil {
				return err
			}
			s.Paused = current.Paused
			for k, v := range current.Cooldowns {
				if strings.HasPrefix(k, "delivered:") && v.After(s.Cooldowns[k]) && (s.LastPoll.IsZero() || v.After(s.LastPoll.Add(-24*time.Hour))) {
					s.Cooldowns[k] = v
				}
			}
		}
		return r.write(s)
	})
}
func (r Repository) Pause(paused bool) error {
	return r.locked(func() error {
		s, err := r.load()
		if err != nil {
			return err
		}
		s.Paused = paused
		return r.write(s)
	})
}

// Audit bounds local event history to two 1MiB files; saved Herdr history is untouched.
func (r Repository) Audit(e Event) error {
	return r.locked(func() error {
		p := filepath.Join(r.Directory, "watchdog-audit.jsonl")
		if info, err := os.Stat(p); err == nil && info.Size() >= 1<<20 {
			if err = os.Rename(p, p+".1"); err != nil {
				return err
			}
		}
		f, err := os.OpenFile(p, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		defer f.Close()
		return json.NewEncoder(f).Encode(e)
	})
}

type Lock struct{ file *os.File }

func Acquire(directory string) (*Lock, error) {
	if err := os.MkdirAll(directory, 0700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(directory, "watchdog.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("watchdog already running: %w", err)
	}
	_ = f.Truncate(0)
	_, _ = fmt.Fprintf(f, "%d %s\n", os.Getpid(), time.Now().UTC().Format(time.RFC3339))
	return &Lock{f}, nil
}
func (l *Lock) Close() error { return l.file.Close() }
