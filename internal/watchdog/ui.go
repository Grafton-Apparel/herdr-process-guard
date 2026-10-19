package watchdog

import (
	"fmt"
	tea "github.com/charmbracelet/bubbletea"
	"strings"
	"time"
)

func StatusText(s State, c Config) string {
	mode := "notifications only"
	if c.Cleanup {
		mode = "orphan cleanup enabled"
	}
	if s.Paused {
		mode += " (cleanup paused)"
	}
	poll := "no observation yet"
	if !s.LastPoll.IsZero() {
		poll = s.LastPoll.Local().Format(time.RFC3339)
	}
	orphans, attempts := 0, 0
	for _, r := range s.Records {
		if !r.OrphanSince.IsZero() {
			orphans++
		}
		if r.Attempted {
			attempts++
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Herdr Process Guard watchdog\nMode: %s\nLast observation: %s\nRecorded helpers: %d; observed orphans: %d; attempted identities: %d\nPoll: %ds; orphan and quiet window: %ds\n", mode, poll, len(s.Records), orphans, attempts, c.PollSeconds, c.OrphanSeconds)
	if len(s.Warnings) > 0 {
		fmt.Fprintf(&b, "Warnings: %d\n", len(s.Warnings))
		for i, w := range s.Warnings {
			if i >= 12 {
				fmt.Fprintln(&b, "See watchdog-report for remaining warnings.")
				break
			}
			fmt.Fprintln(&b, SafeText(w))
		}
	}
	return b.String()
}

type statusTick time.Time
type dashboard struct {
	repo   Repository
	config Config
	state  State
	err    error
}

func (d dashboard) Init() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg { return statusTick(t) })
}
func (d dashboard) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch m := msg.(type) {
	case tea.KeyMsg:
		switch m.String() {
		case "q", "esc", "ctrl+c":
			return d, tea.Quit
		case "p":
			d.err = d.repo.Pause(true)
		case "r":
			d.err = d.repo.Pause(false)
		}
	case statusTick:
	}
	s, err := d.repo.Load()
	if err != nil {
		d.err = err
	} else {
		d.state = s
	}
	return d, d.Init()
}
func (d dashboard) View() string {
	s := StatusText(d.state, d.config) + "\np: pause cleanup   r: resume cleanup   q: close\n"
	if d.err != nil {
		s += "\n" + SafeText(d.err.Error()) + "\n"
	}
	return s
}
func Dashboard(repo Repository, c Config) error {
	s, err := repo.Load()
	if err != nil {
		return err
	}
	_, err = tea.NewProgram(dashboard{repo: repo, config: c, state: s}, tea.WithAltScreen()).Run()
	return err
}
