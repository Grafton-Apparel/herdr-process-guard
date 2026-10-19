package watchdog

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const ServiceName = "herdr-process-guard.service"

type Service struct {
	Home, Executable, StateDir string
	Run                        func(...string) error
}

func (s Service) BinaryPath() string {
	return filepath.Join(s.Home, ".local", "lib", "herdr-process-guard", "herdr-process-guard")
}
func (s Service) UnitPath() string {
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		base = filepath.Join(s.Home, ".config")
	}
	return filepath.Join(base, "systemd", "user", ServiceName)
}
func unitQuote(s string) (string, error) {
	if strings.ContainsAny(s, "\n\r\x00") {
		return "", fmt.Errorf("newline in service path")
	}
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, `%`, `%%`).Replace(s) + `"`, nil
}
func (s Service) Install() error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("user service requires Linux systemd")
	}
	binary, err := unitQuote(s.BinaryPath())
	if err != nil {
		return err
	}
	state, err := unitQuote("HERDR_PLUGIN_STATE_DIR=" + s.StateDir)
	if err != nil {
		return err
	}
	unit := "[Unit]\nDescription=Herdr Process Guard conservative watchdog\nAfter=default.target\n\n[Service]\nType=simple\nExecStart=" + binary + " watch\nEnvironment=" + state + "\nRestart=on-failure\nRestartSec=10\nTimeoutStopSec=30\nKillMode=control-group\nUMask=0077\nNoNewPrivileges=true\n\n[Install]\nWantedBy=default.target\n"
	for _, key := range []string{"XDG_CONFIG_HOME", "XDG_RUNTIME_DIR", "XDG_CACHE_HOME", "XDG_STATE_HOME", "HERDR_CONFIG_PATH"} {
		if value := os.Getenv(key); value != "" {
			q, err := unitQuote(key + "=" + value)
			if err != nil {
				return err
			}
			unit = strings.Replace(unit, "Restart=on-failure", "Environment="+q+"\nRestart=on-failure", 1)
		}
	}
	if err = os.MkdirAll(filepath.Dir(s.BinaryPath()), 0700); err != nil {
		return err
	}
	source, err := os.Open(s.Executable)
	if err != nil {
		return err
	}
	defer source.Close()
	target, err := os.CreateTemp(filepath.Dir(s.BinaryPath()), ".binary-*")
	if err != nil {
		return err
	}
	defer os.Remove(target.Name())
	defer target.Close()
	if _, err = io.Copy(target, source); err != nil {
		return err
	}
	if err = target.Chmod(0755); err != nil {
		return err
	}
	if err = target.Sync(); err != nil {
		return err
	}
	if err = target.Close(); err != nil {
		return err
	}
	if err = os.Rename(target.Name(), s.BinaryPath()); err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(s.UnitPath()), 0700); err != nil {
		return err
	}
	if err = os.WriteFile(s.UnitPath(), []byte(unit), 0600); err != nil {
		return err
	}
	return s.Run("daemon-reload")
}
func (s Service) Ensure() error {
	if runtime.GOOS != "linux" {
		return nil
	}
	if _, err := os.Stat(s.UnitPath()); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	return s.Run("start", "--no-block", ServiceName)
}
