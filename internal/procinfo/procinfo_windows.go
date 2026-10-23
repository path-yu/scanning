//go:build windows

package procinfo

import (
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

const (
	tcpTableOwnerPidAll            = 5
	errorInsufficientBuffer        = 122
	processQueryLimitedInformation = 0x1000
)

var (
	iphlpapi                       = syscall.NewLazyDLL("iphlpapi.dll")
	kernel32                       = syscall.NewLazyDLL("kernel32.dll")
	procGetExtendedTCPTable        = iphlpapi.NewProc("GetExtendedTcpTable")
	procOpenProcess                = kernel32.NewProc("OpenProcess")
	procQueryFullProcessImageNameW = kernel32.NewProc("QueryFullProcessImageNameW")
	procCloseHandle                = kernel32.NewProc("CloseHandle")
	procCreateToolhelp32Snapshot   = kernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32FirstW            = kernel32.NewProc("Process32FirstW")
	procProcess32NextW             = kernel32.NewProc("Process32NextW")
)

const th32csSnapProcess = 0x00000002

type processEntry32W struct {
	Size            uint32
	CntUsage        uint32
	ProcessID       uint32
	DefaultHeapID   uintptr
	ModuleID        uint32
	CntThreads      uint32
	ParentProcessID uint32
	PriClassBase    int32
	Flags           uint32
	ExeFile         [260]uint16
}

type mibTCPRowOwnerPid struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPID  uint32
}

func lookupProcess(clientIP string, clientPort, proxyPort int) (Info, bool) {
	ip := net.ParseIP(clientIP)
	if ip == nil || ip.To4() == nil {
		return Info{}, false
	}
	rows, err := tcpRows()
	if err != nil {
		return Info{}, false
	}
	target := ipv4ToDWORD(ip.To4())
	for _, row := range rows {
		if row.LocalAddr != target {
			continue
		}
		if decodePort(row.LocalPort) != clientPort {
			continue
		}
		if proxyPort > 0 && decodePort(row.RemotePort) != proxyPort {
			continue
		}
		return processInfo(row.OwningPID), true
	}
	return Info{}, false
}

func tcpRows() ([]mibTCPRowOwnerPid, error) {
	var size uint32
	ret, _, _ := procGetExtendedTCPTable.Call(
		0,
		uintptr(unsafe.Pointer(&size)),
		1,
		uintptr(syscall.AF_INET),
		tcpTableOwnerPidAll,
		0,
	)
	if ret != errorInsufficientBuffer || size < 4 {
		return nil, fmt.Errorf("GetExtendedTcpTable 获取缓冲区失败: %d", ret)
	}
	buf := make([]byte, size)
	ret, _, _ = procGetExtendedTCPTable.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		1,
		uintptr(syscall.AF_INET),
		tcpTableOwnerPidAll,
		0,
	)
	if ret != 0 {
		return nil, fmt.Errorf("GetExtendedTcpTable 失败: %d", ret)
	}
	count := *(*uint32)(unsafe.Pointer(&buf[0]))
	if count == 0 {
		return nil, nil
	}
	return unsafe.Slice((*mibTCPRowOwnerPid)(unsafe.Pointer(&buf[4])), int(count)), nil
}

func processInfo(pid uint32) Info {
	info := Info{PID: int(pid)}
	if pid == 0 {
		return info
	}
	handle, _, _ := procOpenProcess.Call(processQueryLimitedInformation, 0, uintptr(pid))
	if handle == 0 {
		return info
	}
	defer procCloseHandle.Call(handle)

	buf := make([]uint16, 1024)
	length := uint32(len(buf))
	ret, _, _ := procQueryFullProcessImageNameW.Call(handle, 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&length)))
	if ret == 0 {
		return info
	}
	path := syscall.UTF16ToString(buf[:length])
	if path == "" {
		return info
	}
	info.Path = path
	info.Name = filepath.Base(path)
	return info
}

func processIDsByPath(path string) []int {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	target := filepath.Clean(path)
	base := filepath.Base(target)
	snapshot, _, _ := procCreateToolhelp32Snapshot.Call(th32csSnapProcess, 0)
	if snapshot == 0 || snapshot == ^uintptr(0) {
		return nil
	}
	defer procCloseHandle.Call(snapshot)

	entry := processEntry32W{Size: uint32(unsafe.Sizeof(processEntry32W{}))}
	ok, _, _ := procProcess32FirstW.Call(snapshot, uintptr(unsafe.Pointer(&entry)))
	var out []int
	for ok != 0 {
		name := syscall.UTF16ToString(entry.ExeFile[:])
		if strings.EqualFold(name, base) {
			info := processInfo(entry.ProcessID)
			if info.Path != "" && strings.EqualFold(filepath.Clean(info.Path), target) {
				out = append(out, int(entry.ProcessID))
			}
		}
		entry.Size = uint32(unsafe.Sizeof(processEntry32W{}))
		ok, _, _ = procProcess32NextW.Call(snapshot, uintptr(unsafe.Pointer(&entry)))
	}
	return out
}

func connectionsForPIDs(pids []int) []Connection {
	if len(pids) == 0 {
		return nil
	}
	allowed := make(map[uint32]bool, len(pids))
	for _, pid := range pids {
		if pid > 0 {
			allowed[uint32(pid)] = true
		}
	}
	rows, err := tcpRows()
	if err != nil {
		return nil
	}
	out := make([]Connection, 0, 8)
	for _, row := range rows {
		if !allowed[row.OwningPID] {
			continue
		}
		out = append(out, Connection{
			PID:        int(row.OwningPID),
			LocalIP:    ipv4FromDWORD(row.LocalAddr),
			LocalPort:  decodePort(row.LocalPort),
			RemoteIP:   ipv4FromDWORD(row.RemoteAddr),
			RemotePort: decodePort(row.RemotePort),
			State:      tcpStateName(row.State),
		})
	}
	return out
}

func tcpStateName(state uint32) string {
	switch state {
	case 1:
		return "CLOSED"
	case 2:
		return "LISTEN"
	case 3:
		return "SYN_SENT"
	case 4:
		return "SYN_RCVD"
	case 5:
		return "ESTABLISHED"
	case 6:
		return "FIN_WAIT1"
	case 7:
		return "FIN_WAIT2"
	case 8:
		return "CLOSE_WAIT"
	case 9:
		return "CLOSING"
	case 10:
		return "LAST_ACK"
	case 11:
		return "TIME_WAIT"
	case 12:
		return "DELETE_TCB"
	default:
		return fmt.Sprintf("STATE_%d", state)
	}
}

func decodePort(port uint32) int {
	p := uint16(port)
	return int(p>>8 | p<<8)
}

func ipv4ToDWORD(ip net.IP) uint32 {
	return uint32(ip[0]) | uint32(ip[1])<<8 | uint32(ip[2])<<16 | uint32(ip[3])<<24
}

func ipv4FromDWORD(value uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(value), byte(value>>8), byte(value>>16), byte(value>>24))
}
