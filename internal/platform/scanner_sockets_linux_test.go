//go:build linux

package platform

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestLinuxSocketsScanSharedFileTableOnce(t *testing.T) {
	s := procFixture(t)
	fixtureProcess(t, s, 42)
	fixtureThread(t, s, 42, 43)
	writeFixture(t, s.ProcRoot, "42/net/tcp", "header\n 0: 0100007F:1F90 0200007F:C350 01 0:0 0:0 0 0 0 12345\n")
	if err := os.Symlink("socket:[12345]", filepath.Join(s.ProcRoot, "42/fd/3")); err != nil {
		t.Fatal(err)
	}
	// Thread 43 shares the leader's table, so its fd directory is never read.
	if err := os.RemoveAll(filepath.Join(s.ProcRoot, "42/task/43/fd")); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(s.ProcRoot, "42")
	if _, err := readProcessSocketsWithTables(dir, s.UID, readSocketTables); err == nil {
		t.Fatal("per-thread scan read a missing fd directory")
	}
	compared := 0
	sockets, err := readProcessSocketsWith(dir, s.UID, readSocketTables, func(a, b int) (bool, error) {
		compared++
		return true, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(sockets) != 1 || sockets[0].State != "ESTABLISHED" {
		t.Fatalf("shared table sockets = %+v", sockets)
	}
	if compared != 2 { // grouping, then the re-check after the read
		t.Fatalf("file table comparisons = %d, want 2", compared)
	}
}

func TestLinuxSocketsRejectFileTableSplitDuringRead(t *testing.T) {
	s := procFixture(t)
	fixtureProcess(t, s, 42)
	fixtureThread(t, s, 42, 43)
	calls := 0
	_, err := readProcessSocketsWith(filepath.Join(s.ProcRoot, "42"), s.UID, readSocketTables, func(a, b int) (bool, error) {
		calls++
		return calls == 1, nil
	})
	if err == nil {
		t.Fatal("thread left the shared file table during the read")
	}
}

func TestSocketTableCacheSharesNamespaceAndRereadsMisses(t *testing.T) {
	s := procFixture(t)
	writeFixture(t, s.ProcRoot, "netns-one", "namespace fixture")
	tasks := map[int]string{}
	for _, pid := range []int{42, 44} {
		fixtureProcess(t, s, pid)
		task := filepath.Join(s.ProcRoot, strconv.Itoa(pid), "task", strconv.Itoa(pid))
		if err := os.MkdirAll(filepath.Join(task, "ns"), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(s.ProcRoot, "netns-one"), filepath.Join(task, "ns/net")); err != nil {
			t.Fatal(err)
		}
		tasks[pid] = task
	}
	writeFixture(t, s.ProcRoot, "42/net/tcp", "header\n 0: 0100007F:1F90 0200007F:C350 01 0:0 0:0 0 0 0 12345\n")
	cache := newSocketTableCache()
	defer cache.Close()
	if _, err := cache.read(tasks[42], map[string]bool{"12345": true}); err != nil {
		t.Fatal(err)
	}
	// Same namespace: 44's own tables are not read while the cached one resolves.
	if err := os.Remove(filepath.Join(s.ProcRoot, "44/net/tcp")); err != nil {
		t.Fatal(err)
	}
	if sockets, err := cache.read(tasks[44], map[string]bool{"12345": true}); err != nil || len(sockets) != 1 {
		t.Fatalf("cached namespace table: %+v, %v", sockets, err)
	}
	// A socket opened after the cached read gets a fresh table.
	writeFixture(t, s.ProcRoot, "44/net/tcp", "header\n 0: 0100007F:0050 00000000:0000 0A 0:0 0:0 0 0 0 67890\n")
	sockets, err := cache.read(tasks[44], map[string]bool{"67890": true})
	if err != nil || len(sockets) != 1 || !sockets[0].Listen {
		t.Fatalf("fresh read after a miss: %+v, %v", sockets, err)
	}
	if _, err := cache.read(tasks[44], map[string]bool{"11111": true}); err == nil {
		t.Fatal("unknown inode resolved")
	}
}
