package watchdog

import (
	"context"
	"errors"
	"fmt"
	"github.com/Efeguclu1/herdr-process-guard/internal/model"
	"runtime"
	"time"
)

type Pin interface {
	Revalidate() error
	SIGTERM() error
	Close() error
}
type Runner struct {
	Context context.Context
	Config  Config
	Repo    Repository
	Now     func() time.Time
	Source  func() (Snapshot, error)
	Pin     func(model.Process) (Pin, error)
	Notify  func(Event) error
	Sleep   func(time.Duration)
}

func (r *Runner) event(e Event) error {
	if e.At.IsZero() {
		e.At = r.Now().UTC()
	}
	current, err := r.Repo.Load()
	if err != nil {
		return err
	}
	key := "delivered:" + e.Kind + ":" + e.Key
	if last, ok := current.Cooldowns[key]; ok && e.At.Sub(last) < r.Config.Cooldown() {
		return nil
	}
	current.Cooldowns[key] = e.At
	if err = r.Repo.Save(current); err != nil {
		return err
	}
	if err = r.Repo.Audit(e); err != nil {
		return err
	}
	if r.Notify != nil {
		if err = r.Notify(e); err != nil {
			return r.Repo.Audit(Event{Kind: "notification-error", Key: e.Key, At: e.At, Summary: SafeText(err.Error())})
		}
	}
	return nil
}
func (r *Runner) Once(st *State) error {
	current, err := r.Repo.Load()
	if err != nil {
		return err
	}
	st.Paused = current.Paused
	snap, err := r.Source()
	if err != nil {
		return err
	}
	events := Observe(st, snap, r.Now().UTC(), r.Config)
	if err = r.Repo.Save(*st); err != nil {
		return err
	}
	for _, e := range events {
		if err = r.event(e); err != nil {
			return err
		}
	}
	if !r.Config.Cleanup || st.Paused {
		return nil
	}
	if runtime.GOOS != "linux" {
		return errors.New("automatic cleanup requires Linux")
	}
	for _, candidate := range Candidates(*st, snap, r.Now().UTC(), r.Config) {
		if err = r.cleanup(st, candidate); err != nil {
			if err = r.event(Event{Kind: "cleanup-blocked", Key: "blocked:" + fmt.Sprint(candidate.Root), Socket: candidate.Socket, Pane: candidate.Pane, PID: candidate.Root, Summary: SafeText(err.Error())}); err != nil {
				return err
			}
		}
	}
	return nil
}
func (r *Runner) validate(st State, want Candidate) (Candidate, error) {
	if r.Context != nil && r.Context.Err() != nil {
		return Candidate{}, r.Context.Err()
	}
	s, err := r.Source()
	if err != nil {
		return Candidate{}, err
	}
	for _, got := range Candidates(st, s, r.Now().UTC(), r.Config) {
		if got.Root == want.Root && SameCandidate(want, got) {
			return got, nil
		}
	}
	return Candidate{}, errors.New("fresh session, policy, activity or tree validation rejected cleanup")
}
func (r *Runner) cleanup(st *State, want Candidate) error {
	if _, err := r.validate(*st, want); err != nil {
		return err
	}
	pins := []Pin{}
	defer func() {
		for _, p := range pins {
			_ = p.Close()
		}
	}()
	for _, p := range want.Members {
		pin, err := r.Pin(p)
		if err != nil {
			return err
		}
		pins = append(pins, pin)
	}
	if _, err := r.validate(*st, want); err != nil {
		return err
	}
	latest, err := r.Repo.Load()
	if err != nil {
		return err
	}
	if latest.Paused {
		return errors.New("automatic cleanup paused")
	}
	// Record BEFORE signaling. Even a crash or a partial pass cannot repeat an attempt.
	for _, p := range want.Members {
		k := p.Key.String()
		o := st.Records[k]
		o.Attempted = true
		st.Attempts[k] = true
		st.Records[k] = o
	}
	if err = r.Repo.Save(*st); err != nil {
		return fmt.Errorf("persist attempt: %w", err)
	}
	if err = r.Repo.Audit(Event{Kind: "termination-attempt", Key: fmt.Sprint(want.Root), At: r.Now().UTC(), Socket: want.Socket, Pane: want.Pane, PID: want.Root, Summary: "Durable attempt recorded; validating before pidfd SIGTERM"}); err != nil {
		return err
	}
	// State writes can stall. Recheck all sessions and marks after durable writes.
	validation := *st
	validation.Records = map[string]Record{}
	validation.Attempts = map[string]bool{}
	for k, v := range st.Records {
		v.Attempted = false
		validation.Records[k] = v
	}
	if _, err = r.validate(validation, want); err != nil {
		return err
	}
	latest, err = r.Repo.Load()
	if err != nil {
		return err
	}
	if latest.Paused {
		return errors.New("automatic cleanup paused")
	}
	for _, p := range pins {
		if err = p.Revalidate(); err != nil {
			return err
		}
	}
	if r.Context != nil && r.Context.Err() != nil {
		return r.Context.Err()
	}
	// All pins remain held. SIGTERM itself revalidates the exact process identity.
	for i := len(pins) - 1; i >= 0; i-- {
		if r.Context != nil && r.Context.Err() != nil {
			return r.Context.Err()
		}
		if err = pins[i].SIGTERM(); err != nil {
			return err
		}
	}
	if r.Sleep != nil {
		r.Sleep(time.Duration(r.Config.GraceSeconds) * time.Second)
	}
	survivors, err := r.Source()
	if err != nil {
		return r.event(Event{Kind: "survivor", Key: fmt.Sprint(want.Root), Socket: want.Socket, Pane: want.Pane, PID: want.Root, Summary: "SIGTERM sent; survivor snapshot unavailable, no further automatic attempt"})
	}
	count := 0
	for _, p := range want.Members {
		if alive(survivors, p.Key) {
			count++
		}
	}
	return r.event(Event{Kind: "termination", Key: fmt.Sprint(want.Root), Socket: want.Socket, Pane: want.Pane, PID: want.Root, Summary: fmt.Sprintf("pidfd SIGTERM sent; %d survivors; no automatic retry or escalation", count)})
}
func (r *Runner) Watch(ctx context.Context, configPath string) error {
	r.Context = ctx
	st, err := r.Repo.Load()
	if err != nil {
		return err
	}
	ResetContinuity(&st)
	for {
		if ctx.Err() != nil {
			return nil
		}
		cfg, err := LoadConfig(configPath)
		if err != nil {
			return err
		}
		r.Config = cfg
		if err = r.Once(&st); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if auditErr := r.event(Event{Kind: "poll-error", Key: "poll-error", Summary: SafeText(err.Error())}); auditErr != nil {
				return auditErr
			}
			ResetContinuity(&st)
		}
		timer := time.NewTimer(r.Config.Poll())
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}
