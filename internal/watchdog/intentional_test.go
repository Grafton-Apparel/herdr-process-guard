package watchdog

import (
	"github.com/Efeguclu1/herdr-process-guard/internal/store"
	"testing"
	"time"
)

func TestRecordedHelperCanBeMarkedAfterPaneDisappears(t *testing.T) {
	t.Setenv("HERDR_PLUGIN_STATE_DIR", t.TempDir())
	st, s, now := observeMature(t, nil, false)
	handled, err := MarkRecorded(st, s.Processes, 30, false, "", now)
	if err != nil || !handled {
		t.Fatal(handled, err)
	}
	dir, _ := store.SessionDirectory("/s")
	saved, err := store.New(dir).Load()
	if err != nil || len(saved.Approvals) != 1 {
		t.Fatal(saved, err)
	}
	handled, err = MarkRecorded(st, s.Processes, 30, true, "", time.Now())
	if err != nil || !handled {
		t.Fatal(handled, err)
	}
	saved, _ = store.New(dir).Load()
	if len(saved.Approvals) != 0 {
		t.Fatal("unmark failed")
	}
}
