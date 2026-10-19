package watchdog

import (
	"github.com/Efeguclu1/herdr-process-guard/internal/model"
	"github.com/Efeguclu1/herdr-process-guard/internal/store"
	"time"
)

// MarkRecorded extends the manual approval registry to previously attributed non-listeners.
func MarkRecorded(st State, processes map[int]model.Process, pid int, unmark bool, extraSocket string, now time.Time) (bool, error) {
	if unmark {
		sockets := map[string]bool{}
		if extraSocket != "" {
			sockets[extraSocket] = true
		}
		for _, r := range st.Records {
			sockets[r.Socket] = true
		}
		removed := false
		for socket := range sockets {
			dir, err := store.SessionDirectory(socket)
			if err != nil {
				return true, err
			}
			_, err = store.New(dir).Update(func(s *model.PersistedState) error {
				for k, a := range s.Approvals {
					if a.Root.PID == pid {
						delete(s.Approvals, k)
						removed = true
					}
				}
				return nil
			})
			if err != nil {
				return true, err
			}
		}
		return removed, nil
	}
	p, ok := processes[pid]
	if !ok {
		return false, nil
	}
	r, ok := st.Records[p.Key.String()]
	if !ok || !exact(r.Last, p) {
		return false, nil
	}
	members := []model.ProcessKey{}
	for _, q := range processes {
		if ancestor(Snapshot{Processes: processes}, q.Key.PID, pid) {
			members = append(members, q.Key)
		}
	}
	dir, err := store.SessionDirectory(r.Socket)
	if err != nil {
		return true, err
	}
	_, err = store.New(dir).Update(func(s *model.PersistedState) error {
		s.Approvals[p.Key.String()] = model.Approval{Root: p.Key, Members: members, MarkedAt: now}
		return nil
	})
	return true, err
}
