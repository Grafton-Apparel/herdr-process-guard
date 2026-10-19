//go:build linux

package platform

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/Efeguclu1/herdr-process-guard/internal/model"
	"golang.org/x/sys/unix"
)

var errGraphIncomplete = errors.New("process ancestry graph incomplete")
var errMixedCredentials = errors.New("mixed process credentials")

const maxProcFile = 4 * 1024 * 1024
const maxProcEntries = 131072

func readBounded(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxProcFile+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxProcFile {
		return nil, fmt.Errorf("%s exceeds read limit", path)
	}
	return b, nil
}
func readEntries(path string) ([]os.DirEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	entries, err := f.ReadDir(maxProcEntries + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(entries) > maxProcEntries {
		return nil, fmt.Errorf("%s exceeds entry limit", path)
	}
	return entries, nil
}
func (s *Scanner) procRoot() string {
	if s.ProcRoot != "" {
		return s.ProcRoot
	}
	return "/proc"
}

func (s *Scanner) procInfo() (string, int64, uint64, error) {
	root := s.procRoot()
	id, err := readBounded(filepath.Join(root, "sys/kernel/random/boot_id"))
	if err != nil {
		return "", 0, 0, err
	}
	bootID := strings.TrimSpace(string(id))
	if bootID == "" || strings.ContainsAny(bootID, ": \t\n") {
		return "", 0, 0, errors.New("invalid boot ID")
	}
	stat, err := readBounded(filepath.Join(root, "stat"))
	if err != nil {
		return "", 0, 0, err
	}
	var boot int64
	for _, line := range strings.Split(string(stat), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[0] == "btime" {
			boot, err = strconv.ParseInt(f[1], 10, 64)
			if err != nil {
				return "", 0, 0, err
			}
		}
	}
	if boot <= 0 {
		return "", 0, 0, errors.New("missing boot time")
	}
	ticks := s.ClockTicks
	if ticks == 0 {
		aux, err := readBounded(filepath.Join(root, "self/auxv"))
		if err != nil {
			return "", 0, 0, err
		}
		word := strconv.IntSize / 8
		if len(aux)%(word*2) != 0 {
			return "", 0, 0, errors.New("invalid auxv")
		}
		value := func(b []byte) uint64 {
			if word == 8 {
				return binary.NativeEndian.Uint64(b)
			}
			return uint64(binary.NativeEndian.Uint32(b))
		}
		for i := 0; i+word*2 <= len(aux); i += word * 2 {
			if value(aux[i:]) == 17 {
				ticks = value(aux[i+word:])
				break
			}
		}
	}
	if ticks == 0 || ticks > 1000000 {
		return "", 0, 0, errors.New("invalid or missing CLK_TCK")
	}
	return bootID, boot, ticks, nil
}

type linuxStat struct {
	pid, ppid, pgid, sid     int
	name, state              string
	start, user, system, rss uint64
}

func parseLinuxStat(data []byte) (linuxStat, error) {
	text := strings.TrimSpace(string(data))
	open := strings.Index(text, " (")
	close := strings.LastIndex(text, ") ")
	if open < 1 || close <= open {
		return linuxStat{}, errors.New("invalid stat command")
	}
	pid, err := strconv.Atoi(text[:open])
	if err != nil || pid <= 0 {
		return linuxStat{}, errors.New("invalid stat PID")
	}
	f := strings.Fields(text[close+2:])
	if len(f) < 22 {
		return linuxStat{}, errors.New("short stat")
	}
	p := linuxStat{pid: pid, name: text[open+2 : close], state: f[0]}
	for index, dst := range map[int]*int{1: &p.ppid, 2: &p.pgid, 3: &p.sid} {
		*dst, err = strconv.Atoi(f[index])
		if err != nil {
			return linuxStat{}, err
		}
	}
	for index, dst := range map[int]*uint64{11: &p.user, 12: &p.system, 19: &p.start, 21: &p.rss} {
		*dst, err = strconv.ParseUint(f[index], 10, 64)
		if err != nil {
			return linuxStat{}, err
		}
	}
	return p, nil
}
func readUID(path string) (int, error) {
	b, err := readBounded(path)
	if err != nil {
		return -1, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) > 0 && f[0] == "Uid:" {
			if len(f) != 5 {
				return -1, errors.New("invalid UID record")
			}
			uid, err := strconv.Atoi(f[1])
			if err != nil || uid < 0 {
				return -1, errors.New("invalid UID")
			}
			for _, v := range f[2:] {
				n, e := strconv.Atoi(v)
				if e != nil || n != uid {
					return uid, errMixedCredentials
				}
			}
			return uid, nil
		}
	}
	return -1, errors.New("missing UID")
}
func (s *Scanner) processesNative() (map[int]model.Process, []string, error) {
	s.GraphComplete = false
	boot, started, ticks, err := s.procInfo()
	if err != nil {
		return nil, nil, fmt.Errorf("read procfs system identity: %w", err)
	}
	entries, err := readEntries(s.procRoot())
	if err != nil {
		return nil, nil, fmt.Errorf("list procfs: %w", err)
	}
	processes := map[int]model.Process{}
	s.GraphComplete = true
	warnings := []string{}
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}
		p, skip, err := s.readProcess(pid, boot, started, ticks)
		if errors.Is(err, errGraphIncomplete) {
			s.GraphComplete = false
		}
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("process %d telemetry unavailable: %v", pid, err))
		}
		if !skip && p.Key.PID != 0 {
			processes[pid] = p
		}
	}
	for pid, p := range processes {
		if parent, ok := processes[p.PPID]; ok {
			parent.Children = append(parent.Children, pid)
			processes[p.PPID] = parent
		}
	}
	for pid, p := range processes {
		sort.Ints(p.Children)
		p.Children = slices.Compact(p.Children)
		processes[pid] = p
	}
	sort.Strings(warnings)
	return processes, warnings, nil
}
func (s *Scanner) readProcess(pid int, boot string, bootTime int64, ticks uint64) (model.Process, bool, error) {
	dir := filepath.Join(s.procRoot(), strconv.Itoa(pid))

	statBytes, err := readBounded(filepath.Join(dir, "stat"))
	if err != nil {
		return model.Process{}, true, errors.Join(errGraphIncomplete, err)
	}
	st, err := parseLinuxStat(statBytes)
	if err != nil || st.pid != pid {
		return model.Process{}, true, errors.Join(errGraphIncomplete, fmt.Errorf("invalid stat for PID %d: %v", pid, err))
	}
	p := model.Process{
		Key: model.ProcessKey{PID: pid, BootID: boot, StartTicks: st.start, StartUnixMS: bootTime*1000 + int64(st.start/ticks)*1000 + int64(st.start%ticks)*1000/int64(ticks)},
		UID: -1, PPID: st.ppid, PGID: st.pgid, SessionID: st.sid, Name: st.name, State: st.state,
		RSSBytes:      st.rss * uint64(os.Getpagesize()),
		CPUTimeMillis: int64(st.user/ticks+st.system/ticks)*1000 + int64(st.user%ticks+st.system%ticks)*1000/int64(ticks),
	}
	uid, err := readUID(filepath.Join(dir, "status"))
	if uid >= 0 && uid != s.UID {
		return model.Process{}, true, nil
	}
	if err != nil && !errors.Is(err, errMixedCredentials) {
		return p, false, errors.Join(errGraphIncomplete, err)
	}
	p.UID = uid
	// Zombies retain ancestry but cannot run, perform I/O, or accept a useful signal.
	// Empty executable/argv/FD data is expected and must not obstruct other trees.
	if st.state == "Z" {
		if e := validateProcessGraph(dir, st, uid); errors.Is(e, errGraphIncomplete) {
			return p, false, e
		}
		return p, false, nil
	}

	var gaps []error
	if err != nil {
		gaps = append(gaps, err)
	}
	p.Executable, err = os.Readlink(filepath.Join(dir, "exe"))
	if err != nil || p.Executable == "" {
		gaps = append(gaps, fmt.Errorf("executable unavailable: %v", err))
	}
	p.ExecutableDevice, p.ExecutableInode, err = executableIdentity(filepath.Join(dir, "exe"))
	if err != nil {
		gaps = append(gaps, fmt.Errorf("executable file identity unavailable: %w", err))
	}
	cmd, err := readBounded(filepath.Join(dir, "cmdline"))
	if err != nil || len(cmd) == 0 {
		gaps = append(gaps, fmt.Errorf("command unavailable: %v", err))
	} else {
		p.Command = strings.ReplaceAll(strings.TrimRight(string(cmd), "\x00"), "\x00", " ")
		p.CommandHash = model.HashCommand(string(cmd))
		p.CommandSummary = sanitizeCommand(p.Command, p.Name)
	}
	p.Children, err = readProcessChildren(dir)
	if err != nil {
		gaps = append(gaps, fmt.Errorf("child membership unavailable: %w", err))
	} else {
		p.ChildrenComplete = true
	}
	p.CWD, err = os.Readlink(filepath.Join(dir, "cwd"))
	if err != nil {
		gaps = append(gaps, fmt.Errorf("cwd unavailable: %w", err))
	}
	if err = readProcessIO(dir, &p); err != nil {
		gaps = append(gaps, fmt.Errorf("I/O unavailable: %w", err))
	} else {
		p.IOComplete = true
	}
	p.Sockets, err = readProcessSockets(dir, uid)
	if err != nil {
		gaps = append(gaps, fmt.Errorf("sockets unavailable: %w", err))
	} else {
		p.SocketsComplete = true
	}
	// Re-read identity after related files to reject PID reuse and ancestry changes.
	if e := validateProcessGraph(dir, st, uid); e != nil {
		if errors.Is(e, errGraphIncomplete) {
			return p, false, e
		}
		gaps = append(gaps, e)
	}
	afterExe, e := os.Readlink(filepath.Join(dir, "exe"))
	if e != nil || afterExe != p.Executable {
		gaps = append(gaps, errors.New("executable unavailable or changed during read"))
	}
	afterDevice, afterInode, e := executableIdentity(filepath.Join(dir, "exe"))
	if e != nil || afterDevice != p.ExecutableDevice || afterInode != p.ExecutableInode {
		gaps = append(gaps, errors.New("executable file identity unavailable or changed during read"))
	}
	afterCmd, e := readBounded(filepath.Join(dir, "cmdline"))
	if e != nil || string(afterCmd) != string(cmd) {
		gaps = append(gaps, errors.New("command unavailable or changed during read"))
	}
	afterChildren, e := readProcessChildren(dir)
	if e != nil || !slices.Equal(afterChildren, p.Children) {
		p.ChildrenComplete = false
		p.Children = append(p.Children, afterChildren...)
		sort.Ints(p.Children)
		p.Children = slices.Compact(p.Children)
		gaps = append(gaps, fmt.Errorf("child membership unavailable or changed during read: %v", e))
	}
	p.TelemetryComplete = len(gaps) == 0
	return p, false, errors.Join(gaps...)
}

// validateProcessGraph also runs for zombies, whose metadata files can disappear
// before the kernel recycles the PID.
func validateProcessGraph(dir string, before linuxStat, uid int) error {
	data, err := readBounded(filepath.Join(dir, "stat"))
	if err != nil {
		return errors.Join(errGraphIncomplete, err)
	}
	after, err := parseLinuxStat(data)
	if err != nil || after.pid != before.pid || after.start != before.start || after.ppid != before.ppid || after.pgid != before.pgid || after.sid != before.sid {
		return errors.Join(errGraphIncomplete, errors.New("process identity changed during read"))
	}
	afterUID, err := readUID(filepath.Join(dir, "status"))
	if (err != nil && !errors.Is(err, errMixedCredentials)) || afterUID != uid {
		return errors.Join(errGraphIncomplete, errors.New("process UID changed during read"))
	}
	return err
}

func readProcessIO(dir string, p *model.Process) error {
	data, err := readBounded(filepath.Join(dir, "io"))
	if err != nil {
		return err
	}
	fields := map[string]*uint64{"read_bytes:": &p.IOReadBytes, "write_bytes:": &p.IOWriteBytes, "rchar:": &p.IOReadChars, "wchar:": &p.IOWriteChars}
	seen := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) != 2 {
			continue
		}
		if dst, ok := fields[f[0]]; ok {
			v, err := strconv.ParseUint(f[1], 10, 64)
			if err != nil || seen[f[0]] {
				return errors.New("invalid I/O counter")
			}
			*dst = v
			seen[f[0]] = true
		}
	}
	if len(seen) != len(fields) {
		return errors.New("missing I/O counters")
	}
	return nil
}

// readProcessChildren includes children forked by any thread. Child PIDs can
// belong to another UID; exposing membership requires no foreign command data.
func readProcessChildren(dir string) ([]int, error) {
	entries, err := readEntries(filepath.Join(dir, "task"))
	if err != nil {
		return nil, err
	}
	children := []int{}
	threads := 0
	for _, entry := range entries {
		tid, err := strconv.Atoi(entry.Name())
		if err != nil || tid <= 0 {
			continue
		}
		threads++
		data, err := readBounded(filepath.Join(dir, "task", entry.Name(), "children"))
		if err != nil {
			return children, err
		}
		for _, value := range strings.Fields(string(data)) {
			pid, err := strconv.Atoi(value)
			if err != nil || pid <= 0 {
				return children, errors.New("invalid child PID")
			}
			children = append(children, pid)
		}
	}
	if threads == 0 {
		return children, errors.New("missing process tasks")
	}
	sort.Ints(children)
	return slices.Compact(children), nil
}

func executableIdentity(path string) (uint64, uint64, error) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return 0, 0, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Ino == 0 {
		return 0, 0, errors.New("invalid executable file identity")
	}
	return uint64(st.Dev), st.Ino, nil
}

type threadIdentity struct {
	TID        int
	StartTicks uint64
}

func readThreadIdentities(dir string, uid int) ([]threadIdentity, error) {
	entries, err := readEntries(filepath.Join(dir, "task"))
	if err != nil {
		return nil, err
	}
	processID, err := strconv.Atoi(filepath.Base(dir))
	if err != nil {
		return nil, err
	}
	threads := []threadIdentity{}
	for _, entry := range entries {
		tid, err := strconv.Atoi(entry.Name())
		if err != nil || tid <= 0 {
			continue
		}
		task := filepath.Join(dir, "task", entry.Name())
		stat, err := readBounded(filepath.Join(task, "stat"))
		if err != nil {
			return nil, err
		}
		identity, err := parseLinuxStat(stat)
		if err != nil || identity.pid != tid {
			return nil, errors.New("invalid thread identity")
		}
		taskUID, err := readUID(filepath.Join(task, "status"))
		if err != nil || taskUID != uid {
			return nil, errors.New("thread credentials unavailable or changed")
		}
		status, err := readBounded(filepath.Join(task, "status"))
		if err != nil {
			return nil, err
		}
		tgid := 0
		for _, line := range strings.Split(string(status), "\n") {
			f := strings.Fields(line)
			if len(f) == 2 && f[0] == "Tgid:" {
				tgid, err = strconv.Atoi(f[1])
				if err != nil {
					return nil, err
				}
			}
		}
		if tgid != processID {
			return nil, errors.New("thread group identity unavailable or changed")
		}
		threads = append(threads, threadIdentity{TID: tid, StartTicks: identity.start})
	}
	if len(threads) == 0 {
		return nil, errors.New("missing process threads")
	}
	slices.SortFunc(threads, func(a, b threadIdentity) int { return a.TID - b.TID })
	return threads, nil
}

func socketInodes(dir string, remaining *int) (map[string]bool, error) {
	// Keep the directory open through readlink. For /proc/self/fd the directory's
	// own FD appears in its listing and must not disappear before readlink.
	f, err := os.Open(filepath.Join(dir, "fd"))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	entries, err := f.ReadDir(maxProcEntries + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	*remaining -= len(entries)
	if len(entries) > maxProcEntries || *remaining < 0 {
		return nil, errors.New("FD entry limit exceeded")
	}
	wanted := map[string]bool{}
	for _, entry := range entries {
		target, err := os.Readlink(filepath.Join(dir, "fd", entry.Name()))
		if err != nil {
			return nil, err
		}
		if strings.HasPrefix(target, "socket:[") && strings.HasSuffix(target, "]") {
			wanted[strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")] = true
		}
	}
	return wanted, nil
}
func readProcessSockets(dir string, uid int) ([]model.Socket, error) {
	return readProcessSocketsWithTables(dir, uid, readSocketTables)
}

type networkNamespaceIdentity struct{ device, inode uint64 }

func namespaceIdentity(path string) (networkNamespaceIdentity, error) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return networkNamespaceIdentity{}, err
	}
	return networkNamespaceIdentity{uint64(st.Dev), st.Ino}, nil
}

func readProcessSocketsWithTables(dir string, uid int, tables func(string, map[string]bool) ([]model.Socket, error)) ([]model.Socket, error) {
	before, err := readThreadIdentities(dir, uid)
	if err != nil {
		return nil, err
	}
	perThread := map[int]map[string]bool{}
	namespaces := map[int]networkNamespaceIdentity{}
	held := map[networkNamespaceIdentity]*os.File{}
	defer func() {
		for _, f := range held {
			_ = f.Close()
		}
	}()
	type tableKey struct {
		namespace networkNamespaceIdentity
		inodes    string
	}
	cache := map[tableKey][]model.Socket{}
	remaining := maxProcEntries
	sockets := []model.Socket{}
	seen := map[model.Socket]bool{}
	for _, thread := range before {
		task := filepath.Join(dir, "task", strconv.Itoa(thread.TID))
		// Pin namespace identities so their inode cannot be recycled while this
		// process snapshot reuses a table. Unknown namespaces stay uncached.
		var namespace networkNamespaceIdentity
		knownNamespace := false
		if f, openErr := os.Open(filepath.Join(task, "ns", "net")); openErr == nil {
			var st unix.Stat_t
			if statErr := unix.Fstat(int(f.Fd()), &st); statErr == nil && st.Ino != 0 {
				namespace = networkNamespaceIdentity{uint64(st.Dev), st.Ino}
				namespaces[thread.TID] = namespace
				knownNamespace = true
				if _, exists := held[namespace]; !exists {
					held[namespace] = f
				} else {
					_ = f.Close()
				}
			} else {
				_ = f.Close()
			}
		}
		wanted, err := socketInodes(task, &remaining)
		if err != nil {
			return nil, err
		}
		perThread[thread.TID] = wanted
		inodes := make([]string, 0, len(wanted))
		for inode := range wanted {
			inodes = append(inodes, inode)
		}
		sort.Strings(inodes)
		key := tableKey{namespace, strings.Join(inodes, ",")}
		found, cached := cache[key]
		if !knownNamespace || !cached {
			found, err = tables(task, wanted)
			if err != nil {
				return nil, err
			}
			if knownNamespace {
				cache[key] = found
			}
		}
		for _, socket := range found {
			if !seen[socket] {
				sockets = append(sockets, socket)
				seen[socket] = true
			}
		}
	}
	after, err := readThreadIdentities(dir, uid)
	if err != nil {
		return nil, err
	}
	if !slices.Equal(before, after) {
		return nil, errors.New("thread identities changed during socket read")
	}
	remaining = maxProcEntries
	for _, thread := range after {
		wanted := perThread[thread.TID]
		task := filepath.Join(dir, "task", strconv.Itoa(thread.TID))
		current, err := socketInodes(task, &remaining)
		if err != nil {
			return nil, err
		}
		if len(current) != len(wanted) {
			return nil, errors.New("thread socket descriptors changed during read")
		}
		for inode := range current {
			if !wanted[inode] {
				return nil, errors.New("thread socket descriptors changed during read")
			}
		}
		if namespace, known := namespaces[thread.TID]; known {
			current, err := namespaceIdentity(filepath.Join(task, "ns", "net"))
			if err != nil || current != namespace {
				return nil, errors.New("thread network namespace changed during socket read")
			}
		}
	}
	final, err := readThreadIdentities(dir, uid)
	if err != nil {
		return nil, err
	}
	if !slices.Equal(before, final) {
		return nil, errors.New("thread identities changed during socket read")
	}
	return sockets, nil
}

func readSocketTables(dir string, wanted map[string]bool) ([]model.Socket, error) {

	// Reading the tables even with no FDs detects inaccessible socket telemetry.
	sockets := []model.Socket{}
	known := map[string]bool{}
	for _, name := range []string{"tcp", "tcp6", "udp", "udp6", "unix"} {
		data, err := readBounded(filepath.Join(dir, "net", name))
		if err != nil {
			return nil, err
		}
		lines := bufio.NewScanner(strings.NewReader(string(data)))
		lines.Buffer(make([]byte, 4096), maxProcFile)
		if !lines.Scan() {
			return nil, fmt.Errorf("empty socket table %s", name)
		}
		for lines.Scan() {
			f := strings.Fields(lines.Text())
			if len(f) == 0 {
				continue
			}
			if name == "unix" {
				if len(f) < 7 {
					return nil, errors.New("invalid unix socket row")
				}
				if wanted[f[6]] {
					known[f[6]] = true
				}
				continue
			}
			if len(f) < 10 {
				return nil, errors.New("invalid network socket row")
			}
			inode := f[9]
			if !wanted[inode] {
				continue
			}
			local, err := decodeEndpoint(f[1])
			if err != nil {
				return nil, err
			}
			remote, err := decodeEndpoint(f[2])
			if err != nil {
				return nil, err
			}
			protocol := "TCP"
			if strings.HasPrefix(name, "udp") {
				protocol = "UDP"
			}
			state := f[3]
			stateValue, stateErr := strconv.ParseUint(state, 16, 8)
			if stateErr != nil || len(state) != 2 || stateValue < 1 || stateValue > 12 {
				return nil, errors.New("invalid socket state")
			}
			switch state {
			case "01":
				state = "ESTABLISHED"
			case "0A":
				state = "LISTEN"
			}
			endpoint := local
			sockets = append(sockets, model.Socket{Protocol: protocol, Local: endpoint, State: state, Listen: state == "LISTEN" || (protocol == "UDP" && strings.HasSuffix(remote, ":0"))})
			known[inode] = true
		}
		if err := lines.Err(); err != nil {
			return nil, err
		}
	}
	for inode := range wanted {
		if !known[inode] {
			return nil, fmt.Errorf("unresolved socket inode %s", inode)
		}
	}
	return sockets, nil
}
func decodeEndpoint(value string) (string, error) {
	parts := strings.Split(value, ":")
	if len(parts) != 2 {
		return "", errors.New("invalid socket address")
	}
	port, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil {
		return "", err
	}
	raw := parts[0]
	if len(raw) != 8 && len(raw) != 32 {
		return "", errors.New("invalid IP length")
	}
	ip := make(net.IP, len(raw)/2)
	for i := 0; i < len(raw); i += 8 {
		word, err := strconv.ParseUint(raw[i:i+8], 16, 32)
		if err != nil {
			return "", err
		}
		binary.NativeEndian.PutUint32(ip[i/2:i/2+4], uint32(word))
	}
	return net.JoinHostPort(ip.String(), strconv.FormatUint(port, 10)), nil
}
