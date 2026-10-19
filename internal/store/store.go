package store

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/Efeguclu1/herdr-process-guard/internal/model"
)

type Store struct {
	Directory string
}

func DefaultDirectory() (string, error) {
	if path := os.Getenv("HERDR_PLUGIN_STATE_DIR"); path != "" {
		return path, nil
	}
	// Herdr 0.9.5 uses config::state_dir(), including on macOS.
	root := os.Getenv("XDG_STATE_HOME")
	if root == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		root = filepath.Join(home, ".local", "state")
	}
	return filepath.Join(root, "herdr", "plugins", "herdr.process-guard"), nil
}

func New(directory string) *Store { return &Store{Directory: directory} }

func (s *Store) statePath() string { return filepath.Join(s.Directory, "state.json") }
func (s *Store) lockPath() string  { return filepath.Join(s.Directory, ".state.lock") }

func (s *Store) Load() (model.PersistedState, error) {
	return s.withLock(func() (model.PersistedState, error) { return s.loadUnlocked() })
}

func (s *Store) Update(update func(*model.PersistedState) error) (model.PersistedState, error) {
	return s.withLock(func() (model.PersistedState, error) {
		state, err := s.loadUnlocked()
		if err != nil {
			return state, err
		}
		if err := update(&state); err != nil {
			return state, err
		}
		state.SchemaVersion = model.SchemaVersion
		state.UpdatedAt = time.Now().UTC()
		if err := s.saveUnlocked(state); err != nil {
			return state, err
		}
		return state, nil
	})
}

func (s *Store) withLock(operation func() (model.PersistedState, error)) (model.PersistedState, error) {
	if err := os.MkdirAll(s.Directory, 0o700); err != nil {
		return model.PersistedState{}, fmt.Errorf("create state directory: %w", err)
	}
	lock, err := os.OpenFile(s.lockPath(), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return model.PersistedState{}, fmt.Errorf("open state lock: %w", err)
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return model.PersistedState{}, fmt.Errorf("lock state: %w", err)
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN) //nolint:errcheck -- best-effort unlock on close
	return operation()
}

func (s *Store) loadUnlocked() (model.PersistedState, error) {
	file, err := os.Open(s.statePath())
	if errors.Is(err, os.ErrNotExist) {
		return model.NewState(), nil
	}
	if err != nil {
		return model.PersistedState{}, fmt.Errorf("open state: %w", err)
	}
	defer file.Close()
	var state model.PersistedState
	decoder := json.NewDecoder(io.LimitReader(file, 32*1024*1024))
	if err := decoder.Decode(&state); err != nil {
		return model.PersistedState{}, fmt.Errorf("decode state: %w", err)
	}
	if state.SchemaVersion != model.SchemaVersion {
		return model.PersistedState{}, fmt.Errorf("unsupported state schema %d", state.SchemaVersion)
	}
	if state.Observations == nil {
		state.Observations = map[string]model.Observation{}
	}
	if state.Approvals == nil {
		state.Approvals = map[string]model.Approval{}
	}
	if state.TerminationAttempts == nil {
		state.TerminationAttempts = map[string]model.TerminationAttempt{}
	}
	return state, nil
}

func (s *Store) saveUnlocked(state model.PersistedState) error {
	temporary, err := os.CreateTemp(s.Directory, ".state-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary state: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	encoder := json.NewEncoder(temporary)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(state); err != nil {
		temporary.Close()
		return fmt.Errorf("encode state: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("sync state: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close state: %w", err)
	}
	if err := os.Rename(temporaryPath, s.statePath()); err != nil {
		return fmt.Errorf("replace state: %w", err)
	}
	return nil
}

// CanonicalSocket makes plugin and service callers use the same socket namespace.
func CanonicalSocket(socket string) (string, error) {
	path, err := filepath.Abs(socket)
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		return resolved, nil
	}
	// A stopped socket has no inode. Resolve its parent when possible.
	if parent, err := filepath.EvalSymlinks(filepath.Dir(path)); err == nil {
		return filepath.Join(parent, filepath.Base(path)), nil
	}
	return filepath.Clean(path), nil
}
func SessionDirectory(socket string) (string, error) {
	if socket == "" {
		return "", errors.New("session socket is required")
	}
	root, err := DefaultDirectory()
	if err != nil {
		return "", err
	}
	path, err := CanonicalSocket(socket)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(path))
	return filepath.Join(root, "sessions", fmt.Sprintf("%x", sum[:16])), nil
}
