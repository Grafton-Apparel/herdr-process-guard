//go:build !linux

package platform

import (
	"errors"
	"github.com/Efeguclu1/herdr-process-guard/internal/model"
)

type PinnedProcess struct{}

func (s *Scanner) Pin(expected model.Process) (*PinnedProcess, error) {
	return nil, errors.New("identity-pinned automatic signals require Linux pidfds")
}
func (p *PinnedProcess) Revalidate() error { return errors.New("process pin unavailable") }
func (p *PinnedProcess) SIGTERM() error    { return errors.New("process pin unavailable") }
func (p *PinnedProcess) Close() error      { return nil }
