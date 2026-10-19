package main

import (
	"context"
	"fmt"
	"github.com/Efeguclu1/herdr-process-guard/internal/herdr"
	"github.com/Efeguclu1/herdr-process-guard/internal/model"
	"github.com/Efeguclu1/herdr-process-guard/internal/platform"
	"github.com/Efeguclu1/herdr-process-guard/internal/store"
	"github.com/Efeguclu1/herdr-process-guard/internal/watchdog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"syscall"
	"time"
)

func watchdogCommand(command string, args []string) (bool, error) {
	if command == "open-watchdog" || command == "open-dashboard" {
		c, err := herdr.NewFromEnvironment()
		if err != nil {
			return true, err
		}
		entry := "watchdog-status"
		if command == "open-dashboard" {
			entry = "dashboard"
		}
		return true, c.OpenDashboard(entry)
	}
	if command == "mark-intentional" || command == "unmark-intentional" {
		pid, err := requiredPID(args)
		if err != nil {
			return true, err
		}
		dir, err := store.DefaultDirectory()
		if err != nil {
			return true, err
		}
		st, err := (watchdog.Repository{Directory: dir}).Load()
		if err != nil {
			return true, err
		}
		p, _, err := platform.NewScanner().Processes()
		if err != nil {
			return true, err
		}
		handled, err := watchdog.MarkRecorded(st, p, pid, command == "unmark-intentional", os.Getenv("HERDR_SOCKET_PATH"), time.Now().UTC())
		if handled && err == nil {
			fmt.Printf("Updated shared intentional policy for PID %d.\n", pid)
		}
		return handled, err
	}
	switch command {
	case "watch", "watch-once", "watchdog-status", "watchdog-report", "watchdog-config", "watchdog-dashboard", "pause", "resume", "service-install", "service-start", "service-stop", "service-status", "service-ensure", "service-uninstall":
	default:
		return false, nil
	}
	dir, err := store.DefaultDirectory()
	if err != nil {
		return true, err
	}
	repo := watchdog.Repository{Directory: dir}
	configPath := flagValue(args, "--config", filepath.Join(dir, "watchdog-config.json"))
	cfg, err := watchdog.LoadConfig(configPath)
	if err != nil {
		return true, err
	}
	switch command {
	case "watchdog-config":
		return true, printJSON(cfg)
	case "pause", "resume":
		err = repo.Pause(command == "pause")
		if err == nil {
			fmt.Printf("Automatic cleanup %s; alerts stay active.\n", map[bool]string{true: "paused", false: "resumed"}[command == "pause"])
		}
		return true, err
	case "watchdog-status", "watchdog-report":
		s, err := repo.Load()
		if err != nil {
			return true, err
		}
		if command == "watchdog-report" || hasFlag(args, "--json") {
			return true, printJSON(s)
		}
		fmt.Print(watchdog.StatusText(s, cfg))
		return true, nil
	case "watchdog-dashboard":
		return true, watchdog.Dashboard(repo, cfg)
	}
	if len(command) >= 8 && command[:8] == "service-" {
		home, err := os.UserHomeDir()
		if err != nil {
			return true, err
		}
		exe, err := os.Executable()
		if err != nil {
			return true, err
		}
		service := watchdog.Service{Home: home, Executable: exe, StateDir: dir, Run: func(args ...string) error {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "systemctl", append([]string{"--user"}, args...)...)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			return cmd.Run()
		}}
		switch command {
		case "service-install":
			err = service.Install()
		case "service-ensure":
			err = service.Ensure()
		case "service-start":
			err = service.Run("enable", "--now", watchdog.ServiceName)
		case "service-stop":
			err = service.Run("disable", "--now", watchdog.ServiceName)
		case "service-status":
			err = service.Run("status", "--no-pager", watchdog.ServiceName)
		case "service-uninstall":
			if err = service.Run("disable", "--now", watchdog.ServiceName); err == nil {
				err = os.Remove(service.UnitPath())
				if err == nil {
					err = service.Run("daemon-reload")
				}
			}
		}
		return true, err
	}
	// The service has no HERDR_SOCKET_PATH. Construct standalone adapters here.
	cache, err := os.UserCacheDir()
	if err != nil {
		return true, err
	}
	lock, err := watchdog.Acquire(filepath.Join(cache, "herdr-process-guard"))
	if err != nil {
		return true, err
	}
	defer lock.Close()
	scanner := platform.NewScanner()
	collector := watchdog.Collector{Paths: watchdog.Discover, Processes: func() (map[int]model.Process, []string, bool, error) {
		p, w, err := scanner.Processes()
		return p, w, scanner.GraphComplete, err
	}, KnownSockets: func() ([]string, error) {
		s, err := repo.Load()
		if err != nil {
			return nil, err
		}
		seen := map[string]bool{}
		for _, r := range s.Records {
			seen[r.Socket] = true
		}
		paths := []string{}
		for p := range seen {
			paths = append(paths, p)
		}
		sort.Strings(paths)
		return paths, nil
	}}
	runner := watchdog.Runner{Config: cfg, Repo: repo, Now: time.Now, Source: collector.Snapshot, Pin: func(p model.Process) (watchdog.Pin, error) { return scanner.Pin(p) }, Sleep: time.Sleep, Notify: func(e watchdog.Event) error {
		paths, _, err := watchdog.Discover()
		if err != nil {
			return err
		}
		if e.Socket != "" {
			paths = append([]string{e.Socket}, paths...)
		}
		host, _ := os.Hostname()
		body := watchdog.SafeText(host) + " " + watchdog.SafeText(e.Kind) + " session=" + watchdog.SafeText(filepath.Base(filepath.Dir(e.Socket))) + " pane=" + watchdog.SafeText(e.Pane) + ": " + watchdog.SafeText(e.Summary)
		seen := map[string]bool{}
		var last error
		for _, p := range paths {
			if seen[p] {
				continue
			}
			seen[p] = true
			c := herdr.Client{SocketPath: p, Timeout: 2 * time.Second}
			if err = c.Notify("Process Guard", body); err == nil {
				return nil
			}
			last = err
		}
		if last == nil {
			last = fmt.Errorf("no reachable Herdr notification socket")
		}
		return last
	}}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	runner.Context = ctx
	if command == "watch" {
		return true, runner.Watch(ctx, configPath)
	}
	st, err := repo.Load()
	if err != nil {
		return true, err
	}
	watchdog.ResetContinuity(&st)
	if err = runner.Once(&st); err != nil {
		return true, err
	}
	fmt.Print(watchdog.StatusText(st, cfg))
	return true, nil
}
