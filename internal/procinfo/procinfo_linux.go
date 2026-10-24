//go:build linux

package procinfo

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	linuxMu        sync.Mutex
	linuxOwners    map[string]int
	linuxScannedAt time.Time
)

func lookupProcess(clientIP string, clientPort, proxyPort int) (Info, bool) {
	inode, ok := findInode(clientIP, clientPort, proxyPort)
	if !ok {
		return Info{}, false
	}
	pid, ok := ownerOfInode(inode)
	if !ok {
		return Info{}, false
	}
	info := Info{PID: pid}
	if target, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "exe")); err == nil {
		info.Path = target
		info.Name = filepath.Base(target)
	}
	return info, true
}

func processStartTime(pid int) (time.Time, bool) {
	if pid <= 0 {
		return time.Time{}, false
	}
	raw, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return time.Time{}, false
	}
	text := string(raw)
	closeIdx := strings.LastIndex(text, ")")
	if closeIdx < 0 || closeIdx+2 >= len(text) {
		return time.Time{}, false
	}
	fields := strings.Fields(text[closeIdx+2:])
	// 字段从 state（第 3 项）开始，starttime 是第 22 项，即 fields[19]。
	if len(fields) <= 19 {
		return time.Time{}, false
	}
	ticks, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	boot, ok := linuxBootTime()
	if !ok {
		return time.Time{}, false
	}
	const clockTicks = 100 // 常见 Linux USER_HZ
	return boot.Add(time.Duration(ticks) * time.Second / clockTicks), true
}

func linuxBootTime() (time.Time, bool) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return time.Time{}, false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "btime ") {
			continue
		}
		seconds, err := strconv.ParseInt(strings.TrimSpace(strings.TrimPrefix(line, "btime ")), 10, 64)
		if err != nil {
			return time.Time{}, false
		}
		return time.Unix(seconds, 0), true
	}
	return time.Time{}, false
}

func processIDsByPath(path string) []int {
	target := filepath.Clean(strings.TrimSpace(path))
	if target == "" {
		return nil
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var out []int
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		exe, err := os.Readlink(filepath.Join("/proc", entry.Name(), "exe"))
		if err != nil {
			continue
		}
		if strings.EqualFold(filepath.Clean(exe), target) {
			out = append(out, pid)
		}
	}
	return out
}

func connectionsForPIDs(pids []int) []Connection {
	if len(pids) == 0 {
		return nil
	}
	allowed := make(map[int]bool, len(pids))
	for _, pid := range pids {
		if pid > 0 {
			allowed[pid] = true
		}
	}
	data, err := os.ReadFile("/proc/net/tcp")
	if err != nil {
		return nil
	}
	out := make([]Connection, 0, 8)
	for _, line := range strings.Split(string(data), "\n")[1:] {
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}
		state := fields[3]
		if state != "01" && state != "02" {
			continue
		}
		pid, ok := ownerOfInode(fields[9])
		if !ok || !allowed[pid] {
			continue
		}
		localIP, localPort, ok := splitProcAddr(fields[1])
		if !ok {
			continue
		}
		remoteIP, remotePort, ok := splitProcAddr(fields[2])
		if !ok {
			continue
		}
		out = append(out, Connection{
			PID:        pid,
			LocalIP:    localIP,
			LocalPort:  localPort,
			RemoteIP:   remoteIP,
			RemotePort: remotePort,
			State:      procStateName(state),
		})
	}
	return out
}

func procStateName(state string) string {
	switch state {
	case "01":
		return "ESTABLISHED"
	case "02":
		return "SYN_SENT"
	default:
		return "STATE_" + state
	}
}

func findInode(clientIP string, clientPort, proxyPort int) (string, bool) {
	for _, file := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n")[1:] {
			fields := strings.Fields(line)
			if len(fields) < 10 {
				continue
			}
			localIP, localPort, ok := splitProcAddr(fields[1])
			if !ok || localPort != clientPort || localIP != clientIP {
				continue
			}
			if proxyPort > 0 {
				_, remotePort, ok := splitProcAddr(fields[2])
				if !ok || remotePort != proxyPort {
					continue
				}
			}
			return fields[9], true
		}
	}
	return "", false
}

func splitProcAddr(value string) (string, int, bool) {
	parts := strings.Split(value, ":")
	if len(parts) != 2 {
		return "", 0, false
	}
	port, err := strconv.ParseInt(parts[1], 16, 32)
	if err != nil {
		return "", 0, false
	}
	ip := parts[0]
	if len(ip) == 8 {
		addr, err := strconv.ParseUint(ip, 16, 32)
		if err != nil {
			return "", 0, false
		}
		v := uint32(addr)
		return ipv4FromDWORD(v), int(port), true
	}
	return "", int(port), false
}

func ipv4FromDWORD(value uint32) string {
	return strconv.Itoa(int(byte(value))) + "." +
		strconv.Itoa(int(byte(value>>8))) + "." +
		strconv.Itoa(int(byte(value>>16))) + "." +
		strconv.Itoa(int(byte(value>>24)))
}

func ownerOfInode(inode string) (int, bool) {
	linuxMu.Lock()
	defer linuxMu.Unlock()
	if time.Since(linuxScannedAt) < 2*time.Second && linuxOwners != nil {
		pid, ok := linuxOwners[inode]
		return pid, ok
	}
	owners := make(map[string]int)
	entries, err := os.ReadDir("/proc")
	if err == nil {
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			pid, err := strconv.Atoi(entry.Name())
			if err != nil {
				continue
			}
			fdDir := filepath.Join("/proc", entry.Name(), "fd")
			fds, err := os.ReadDir(fdDir)
			if err != nil {
				continue
			}
			for _, fd := range fds {
				target, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
				if err != nil || !strings.HasPrefix(target, "socket:[") {
					continue
				}
				socketInode := strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")
				owners[socketInode] = pid
			}
		}
	}
	linuxOwners = owners
	linuxScannedAt = time.Now()
	pid, ok := owners[inode]
	return pid, ok
}
