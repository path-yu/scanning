package procinfo

// Connection 是某个进程的一条 TCP 连接快照。
type Connection struct {
	PID        int
	LocalIP    string
	LocalPort  int
	RemoteIP   string
	RemotePort int
	State      string
}

// ProcessIDsByPath 返回可执行文件路径匹配的进程 PID（不区分大小写）。
func ProcessIDsByPath(path string) []int {
	return processIDsByPath(path)
}

// ConnectionsForPIDs 返回指定进程当前的 TCP 连接。
func ConnectionsForPIDs(pids []int) []Connection {
	return connectionsForPIDs(pids)
}
