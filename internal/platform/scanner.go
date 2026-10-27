package platform

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Efeguclu1/herdr-process-guard/internal/model"
	"golang.org/x/sys/unix"
)

type Runner func(name string, args ...string) ([]byte, error)

type Scanner struct {
	Run Runner
	UID int
	// ProcRoot and ClockTicks permit procfs fixtures; leave unset for live collection.
	ProcRoot   string
	ClockTicks uint64
	// GraphComplete describes ancestry enumeration from the last native snapshot.
	// Per-process metadata warnings do not imply a graph gap. Read after Processes.
	GraphComplete bool
	// socketTables shares parsed socket tables within one native snapshot.
	socketTables *socketTableCache
}

func NewScanner() *Scanner {
	s := &Scanner{UID: os.Getuid()}
	if runtime.GOOS != "linux" {
		s.Run = runCommand
	}
	return s
}

func runCommand(name string, args ...string) ([]byte, error) {
	command := exec.Command(name, args...)
	command.Stdin = nil
	return command.Output()
}

func (s *Scanner) Processes() (map[int]model.Process, []string, error) {
	if s.Run == nil {
		return s.processesNative()
	}
	output, err := s.Run("/bin/ps", "-ww", "-axo", "pid=,ppid=,pgid=,sess=,uid=,lstart=,state=,rss=,time=,comm=,args=")
	if err != nil {
		return nil, nil, fmt.Errorf("list processes: %w", err)
	}
	processes := map[int]model.Process{}
	scanner := bufio.NewScanner(bytes.NewReader(output))
	scanner.Buffer(make([]byte, 64*1024), 2*1024*1024)
	for scanner.Scan() {
		process, ok := parsePSLine(scanner.Text())
		if !ok || process.UID != s.UID {
			continue
		}
		// macOS `ps` exposes a `sess` display field that is not the numeric
		// session id returned by getsid(2). Herdr uses the latter to own panes.
		if sessionID, sessionErr := unix.Getsid(process.Key.PID); sessionErr == nil {
			process.SessionID = sessionID
		}
		processes[process.Key.PID] = process
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, fmt.Errorf("read process list: %w", err)
	}
	if len(processes) == 0 {
		return processes, []string{"process list was empty"}, nil
	}

	pids := make([]int, 0, len(processes))
	for pid := range processes {
		pids = append(pids, pid)
	}
	sort.Ints(pids)
	warnings := []string{}
	if err := s.attachCWD(processes, pids); err != nil {
		warnings = append(warnings, "working directories unavailable: "+err.Error())
	}
	if err := s.attachSockets(processes, pids); err != nil {
		warnings = append(warnings, "socket activity unavailable: "+err.Error())
	}
	for pid, process := range processes {
		if parent, exists := processes[process.PPID]; exists {
			parent.Children = append(parent.Children, pid)
			sort.Ints(parent.Children)
			processes[parent.Key.PID] = parent
		}
	}
	return processes, warnings, nil
}

func parsePSLine(line string) (model.Process, bool) {
	fields := strings.Fields(line)
	if len(fields) < 15 {
		return model.Process{}, false
	}
	pid, errPID := strconv.Atoi(fields[0])
	ppid, errPPID := strconv.Atoi(fields[1])
	pgid, errPGID := strconv.Atoi(fields[2])
	sid, errSID := strconv.Atoi(fields[3])
	uid, errUID := strconv.Atoi(fields[4])
	if errPID != nil || errPPID != nil || errPGID != nil || errSID != nil || errUID != nil {
		return model.Process{}, false
	}
	started, err := time.ParseInLocation("Mon Jan _2 15:04:05 2006", strings.Join(fields[5:10], " "), time.Local)
	if err != nil {
		return model.Process{}, false
	}
	rssKB, _ := strconv.ParseUint(fields[11], 10, 64)
	cpuMillis := parseCPUTime(fields[12])
	// macOS truncates `comm` even with -ww (for example Python may appear as
	// `/opt/homebrew/Ce`). The first argv token is the more useful executable
	// identity and produces understandable lineage labels.
	executable := fields[13]
	command := strings.Join(fields[14:], " ")
	if command == "" {
		command = executable
	} else if commandFields := strings.Fields(command); len(commandFields) > 0 {
		executable = commandFields[0]
	}
	name := strings.TrimPrefix(filepath.Base(executable), "-")
	return model.Process{
		Key: model.ProcessKey{PID: pid, StartUnixMS: started.UnixMilli()}, PPID: ppid, PGID: pgid,
		SessionID: sid, UID: uid, Name: name, Executable: executable, Command: command,
		CommandSummary: sanitizeCommand(command, name), CommandHash: model.HashCommand(command),
		State: fields[10], RSSBytes: rssKB * 1024, CPUTimeMillis: cpuMillis,
	}, true
}

func parseCPUTime(value string) int64 {
	days := int64(0)
	if parts := strings.SplitN(value, "-", 2); len(parts) == 2 {
		days, _ = strconv.ParseInt(parts[0], 10, 64)
		value = parts[1]
	}
	parts := strings.Split(value, ":")
	var hours, minutes int64
	seconds := float64(0)
	switch len(parts) {
	case 3:
		hours, _ = strconv.ParseInt(parts[0], 10, 64)
		minutes, _ = strconv.ParseInt(parts[1], 10, 64)
		seconds, _ = strconv.ParseFloat(parts[2], 64)
	case 2:
		minutes, _ = strconv.ParseInt(parts[0], 10, 64)
		seconds, _ = strconv.ParseFloat(parts[1], 64)
	default:
		seconds, _ = strconv.ParseFloat(value, 64)
	}
	return ((days*24+hours)*3600+minutes*60)*1000 + int64(seconds*1000)
}

func sanitizeCommand(command, fallback string) string {
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return fallback
	}
	base := filepath.Base(fields[0])
	if len(fields) >= 3 && (base == "npm" || base == "pnpm" || base == "yarn" || base == "bun") && fields[1] == "run" {
		return strings.Join([]string{base, "run", safeToken(fields[2])}, " ")
	}
	if len(fields) >= 2 && (base == "node" || base == "python" || base == "python3" || base == "go") {
		return base + " " + safeToken(filepath.Base(fields[1]))
	}
	return base
}

func safeToken(value string) string {
	if value == "" || strings.ContainsAny(value, "=@:/\\") || len(value) > 64 {
		return "[redacted]"
	}
	return value
}

func pidList(pids []int) string {
	values := make([]string, len(pids))
	for index, pid := range pids {
		values[index] = strconv.Itoa(pid)
	}
	return strings.Join(values, ",")
}

func (s *Scanner) attachCWD(processes map[int]model.Process, pids []int) error {
	output, err := s.Run("/usr/sbin/lsof", "-nP", "-a", "-p", pidList(pids), "-d", "cwd", "-Fpn")
	if err != nil && len(output) == 0 {
		return err
	}
	currentPID := 0
	for _, line := range strings.Split(string(output), "\n") {
		if len(line) < 2 {
			continue
		}
		switch line[0] {
		case 'p':
			currentPID, _ = strconv.Atoi(line[1:])
		case 'n':
			process, ok := processes[currentPID]
			if ok && process.CWD == "" {
				process.CWD = line[1:]
				processes[currentPID] = process
			}
		}
	}
	return nil
}

func (s *Scanner) attachSockets(processes map[int]model.Process, pids []int) error {
	output, err := s.Run("/usr/sbin/lsof", "-nP", "-a", "-p", pidList(pids), "-iTCP", "-iUDP", "-FpcPnT")
	if err != nil && len(output) == 0 {
		// lsof returns 1 when no matching sockets exist.
		return nil
	}
	currentPID := 0
	protocol := ""
	var pending *model.Socket
	flush := func() {
		if pending == nil || currentPID == 0 {
			return
		}
		process, ok := processes[currentPID]
		if ok {
			duplicate := false
			for _, socket := range process.Sockets {
				if socket.Protocol == pending.Protocol && socket.Local == pending.Local && socket.State == pending.State {
					duplicate = true
					break
				}
			}
			if !duplicate {
				process.Sockets = append(process.Sockets, *pending)
			}
			processes[currentPID] = process
		}
		pending = nil
	}
	for _, line := range strings.Split(string(output), "\n") {
		if len(line) < 2 {
			continue
		}
		switch line[0] {
		case 'p':
			flush()
			currentPID, _ = strconv.Atoi(line[1:])
		case 'P':
			protocol = line[1:]
		case 'n':
			flush()
			endpoint := line[1:]
			pending = &model.Socket{Protocol: protocol, Local: endpoint, Listen: protocol == "UDP" && !strings.Contains(endpoint, "->")}
		case 'T':
			if pending != nil && strings.HasPrefix(line, "TST=") {
				pending.State = strings.TrimPrefix(line, "TST=")
				pending.Listen = pending.State == "LISTEN"
			}
		}
	}
	flush()
	return nil
}
