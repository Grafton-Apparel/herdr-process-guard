package watchdog

import (
	"fmt"
	"github.com/Efeguclu1/herdr-process-guard/internal/store"
	"os"
	"path/filepath"
	"sort"
)

// Discover reads only local Herdr control sockets, never client or SSH bridge sockets.
func Discover() (paths, saved []string, err error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, nil, err
	}
	config := os.Getenv("HERDR_CONFIG_PATH")
	if config == "" {
		base := os.Getenv("XDG_CONFIG_HOME")
		if base == "" {
			base = filepath.Join(home, ".config")
		}
		config = filepath.Join(base, "herdr")
	}
	roots := []string{config}
	if runtime := os.Getenv("XDG_RUNTIME_DIR"); runtime != "" {
		roots = append(roots, filepath.Join(runtime, "herdr"))
	}
	seen := map[string]bool{}
	add := func(path string, required bool) error {
		_, e := os.Lstat(path)
		if os.IsNotExist(e) && !required {
			return nil
		}
		if e != nil && !os.IsNotExist(e) {
			return e
		}
		canonical, e := store.CanonicalSocket(path)
		if e != nil {
			return e
		}
		if !seen[canonical] {
			seen[canonical] = true
			paths = append(paths, canonical)
		}
		return nil
	}
	if p := os.Getenv("HERDR_SOCKET_PATH"); p != "" {
		if err = add(p, true); err != nil {
			return
		}
	}
	for _, root := range roots {
		if err = add(filepath.Join(root, "herdr.sock"), false); err != nil {
			return
		}
		entries, e := os.ReadDir(filepath.Join(root, "sessions"))
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			return nil, nil, e
		}
		if len(entries) > 256 {
			return nil, nil, fmt.Errorf("too many saved sessions")
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			dir := filepath.Join(root, "sessions", entry.Name())
			socket := filepath.Join(dir, "herdr.sock")
			if _, e = os.Lstat(socket); os.IsNotExist(e) {
				if _, e = os.Stat(filepath.Join(dir, "session.json")); e == nil {
					saved = append(saved, dir)
				}
				continue
			}
			if err = add(socket, false); err != nil {
				return
			}
		}
	}
	if len(paths) > 64 {
		return nil, nil, fmt.Errorf("too many live session sockets")
	}
	sort.Strings(paths)
	sort.Strings(saved)
	return
}
