//go:build !linux

package platform

import (
	"errors"
	"github.com/Efeguclu1/herdr-process-guard/internal/model"
)

func (s *Scanner) processesNative() (map[int]model.Process, []string, error) {
	return nil, nil, errors.New("native procfs collection requires Linux")
}
