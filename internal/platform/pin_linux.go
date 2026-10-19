//go:build linux

package platform

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"sync"

	"github.com/Efeguclu1/herdr-process-guard/internal/model"
	"golang.org/x/sys/unix"
)

// PinnedProcess holds a Linux pidfd and the immutable observed identity. Call
// Close after use. SIGTERM validates identity and telemetry again under the same
// lock as the pidfd signal; it never falls back to signaling a numeric PID.
// A pidfd prevents PID reuse, but cannot prevent exec or fork after validation.
// The caller must validate the complete target tree and policy before SIGTERM.
type PinnedProcess struct {
	mu       sync.Mutex
	fd       int
	scanner  Scanner
	expected model.Process
}

// Pin accepts only a complete, current-user observation from live /proc. Fixture
// scanners and injected command runners cannot create signal-capable handles.
// Unsupported kernels return an error; automatic cleanup must fail closed.
func (s *Scanner) Pin(expected model.Process) (*PinnedProcess, error) {
	if s.Run != nil || (s.ProcRoot != "" && s.ProcRoot != "/proc") {
		return nil, errors.New("pin requires the live /proc scanner")
	}
	if expected.Key.PID <= 1 || expected.UID != os.Getuid() || s.UID != os.Getuid() || expected.Key.BootID == "" || expected.Key.StartTicks == 0 || expected.Executable == "" || expected.Command == "" || expected.CommandHash == "" || !expected.TelemetryComplete || !expected.SocketsComplete || !expected.IOComplete || !expected.ChildrenComplete {
		return nil, errors.New("incomplete or foreign process identity")
	}
	fd, err := unix.PidfdOpen(expected.Key.PID, 0)
	if err != nil {
		return nil, fmt.Errorf("pidfd_open: %w", err)
	}
	pin := &PinnedProcess{fd: fd, scanner: *s, expected: expected}
	if err := pin.Revalidate(); err != nil {
		pin.Close()
		return nil, err
	}
	return pin, nil
}
func (p *PinnedProcess) revalidateLocked() error {
	if p.fd < 0 {
		return errors.New("process pin is closed")
	}
	fds := []unix.PollFd{{Fd: int32(p.fd), Events: unix.POLLIN}}
	n, err := unix.Poll(fds, 0)
	if err != nil {
		return err
	}
	if n != 0 {
		return errors.New("pinned process exited")
	}
	boot, started, ticks, err := p.scanner.procInfo()
	if err != nil {
		return err
	}
	current, skip, err := p.scanner.readProcess(p.expected.Key.PID, boot, started, ticks)
	if err != nil || skip || !current.TelemetryComplete {
		return fmt.Errorf("pinned process telemetry unavailable: %v", err)
	}
	e := p.expected
	if current.Key != e.Key || current.UID != e.UID || current.Executable != e.Executable || current.Command != e.Command || current.CommandHash != e.CommandHash || current.PPID != e.PPID || current.PGID != e.PGID || current.SessionID != e.SessionID || !slices.Equal(current.Children, e.Children) {
		return errors.New("pinned process identity changed")
	}
	return nil
}

// Revalidate checks boot/start, UID, executable, exact argv hash, displayed
// command, parent/group/session membership, and current telemetry completeness.
func (p *PinnedProcess) Revalidate() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.revalidateLocked()
}

// SIGTERM revalidates and sends only SIGTERM through the held pidfd.
func (p *PinnedProcess) SIGTERM() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.revalidateLocked(); err != nil {
		return err
	}
	return unix.PidfdSendSignal(p.fd, unix.SIGTERM, nil, 0)
}

// Close releases the pidfd. Repeated Close calls succeed.
func (p *PinnedProcess) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.fd < 0 {
		return nil
	}
	fd := p.fd
	p.fd = -1
	return unix.Close(fd)
}
