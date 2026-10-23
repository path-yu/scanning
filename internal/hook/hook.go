// Package hook 负责把 native Hook DLL 注入到目标进程，使直连应用的 TCP 流量
// 改经本机 MITM 代理。它只依赖 Windows 用户态 API，不使用 WinDivert/内核驱动。
package hook

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
)

type Config struct {
	DLLPath string
	Ports   []int
}

type Process struct {
	PID        int    `json:"pid"`
	Name       string `json:"name"`
	Path       string `json:"path,omitempty"`
	Injected   bool   `json:"injected"`
	InjectedAt string `json:"injectedAt,omitempty"`
	Message    string `json:"message,omitempty"`
	Error      string `json:"error,omitempty"`
}

type Status struct {
	Supported bool      `json:"supported"`
	DLLPath   string    `json:"dllPath"`
	DLLExists bool      `json:"dllExists"`
	ProxyAddr string    `json:"proxyAddr"`
	Ports     []int     `json:"ports"`
	LogPath   string    `json:"logPath"`
	Injected  []Process `json:"injected"`
	Message   string    `json:"message,omitempty"`
}

type InjectRequest struct {
	PID  int    `json:"pid"`
	Name string `json:"name"`
	All  bool   `json:"all"`
}

type injectedRecord struct {
	PID        int       `json:"pid"`
	Name       string    `json:"name"`
	Path       string    `json:"path"`
	InjectedAt time.Time `json:"injectedAt"`
}

type Manager struct {
	mu           sync.Mutex
	dataDir      string
	proxyAddr    string
	dllPath      string
	dllExists    bool
	ports        []int
	configDir    string
	logPath      string
	injectedPath string
	injected     map[int]injectedRecord
	configOnce   bool
}

// New 创建注入管理器。dataDir 用于在无法读取 APPDATA 时回退配置目录；
// proxyAddr 是 Scanning 的 HTTP 代理监听地址。
func New(dataDir, proxyAddr string, cfg Config) *Manager {
	m := &Manager{
		dataDir:   dataDir,
		proxyAddr: normalizeProxyAddr(proxyAddr),
		ports:     normalizePorts(cfg.Ports),
		configDir: hookConfigDir(dataDir),
		injected:  make(map[int]injectedRecord),
	}
	m.logPath = filepath.Join(m.configDir, "scanning_hook.log")
	m.injectedPath = filepath.Join(m.configDir, "injected.json")
	m.dllPath, m.dllExists = resolveDLL(cfg.DLLPath)
	m.loadInjected()
	return m
}

func (m *Manager) SetProxyAddr(addr string) {
	normalized := normalizeProxyAddr(addr)
	m.mu.Lock()
	if m.proxyAddr != normalized {
		m.proxyAddr = normalized
		m.configOnce = false
	}
	m.mu.Unlock()
}

func (m *Manager) ProxyAddr() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.proxyAddr
}

func (m *Manager) Ports() []int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]int(nil), m.ports...)
}

func (m *Manager) Status() Status {
	m.mu.Lock()
	proxyAddr := m.proxyAddr
	dllPath := m.dllPath
	dllExists := m.dllExists
	ports := append([]int(nil), m.ports...)
	logPath := m.logPath
	m.mu.Unlock()

	status := Status{
		Supported: supported(),
		DLLPath:   dllPath,
		DLLExists: dllExists,
		ProxyAddr: proxyAddr,
		Ports:     ports,
		LogPath:   logPath,
		Injected:  []Process{},
	}
	if !status.Supported {
		status.Message = "进程注入目前仅支持 Windows"
		return status
	}
	if !dllExists {
		status.Message = "未找到 Hook DLL，请先执行 make hook 或设置 hook.dll_path"
		return status
	}
	status.Injected = m.refreshInjected()
	if len(status.Injected) == 0 {
		status.Message = "Hook DLL 已就绪；注入目标进程后，其 80/443 直连流量将进入代理"
	} else {
		status.Message = fmt.Sprintf("已注入 %d 个进程；80/443 直连流量将进入代理", len(status.Injected))
	}
	return status
}

func (m *Manager) ListProcesses(name string) []Process {
	name = strings.TrimSpace(name)
	if !supported() {
		return nil
	}
	procs := listProcesses(name)
	for i := range procs {
		if procs[i].PID == os.Getpid() {
			continue
		}
		m.markInjectedState(&procs[i])
	}
	sort.Slice(procs, func(i, j int) bool { return procs[i].PID < procs[j].PID })
	return procs
}

func (m *Manager) Inject(req InjectRequest) ([]Process, error) {
	if !supported() {
		return nil, fmt.Errorf("进程注入目前仅支持 Windows")
	}
	if err := m.prepare(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	dllPath := m.dllPath
	dllExists := m.dllExists
	m.mu.Unlock()
	if !dllExists {
		return nil, fmt.Errorf("未找到 Hook DLL：%s", dllPath)
	}

	var targets []Process
	if req.PID > 0 {
		info, ok := processByPID(req.PID)
		if !ok {
			return nil, fmt.Errorf("进程 %d 不存在或无法访问", req.PID)
		}
		targets = []Process{info}
	} else {
		name := strings.TrimSpace(req.Name)
		if name == "" {
			return nil, fmt.Errorf("请填写进程名或 PID")
		}
		targets = listProcesses(name)
		if len(targets) == 0 {
			return nil, fmt.Errorf("未找到进程 %q", name)
		}
		if !req.All && len(targets) > 1 {
			targets = targets[:1]
		}
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("没有可注入的进程")
	}

	results := make([]Process, 0, len(targets))
	for _, target := range targets {
		result := target
		path, already, err := injectPID(target.PID, dllPath)
		if path != "" {
			result.Path = path
		}
		if err != nil {
			result.Error = err.Error()
			results = append(results, result)
			continue
		}
		result.Injected = true
		result.Message = "注入成功"
		if already {
			result.Message = "该进程已加载 Hook DLL"
		}
		now := time.Now()
		m.mu.Lock()
		m.injected[target.PID] = injectedRecord{
			PID:        target.PID,
			Name:       target.Name,
			Path:       result.Path,
			InjectedAt: now,
		}
		m.saveInjectedLocked()
		m.mu.Unlock()
		result.InjectedAt = now.Format(time.RFC3339)
		results = append(results, result)
	}
	return results, nil
}

func (m *Manager) markInjectedState(p *Process) {
	if p == nil || p.PID <= 0 {
		return
	}
	m.mu.Lock()
	record, tracked := m.injected[p.PID]
	m.mu.Unlock()
	if tracked && !record.InjectedAt.IsZero() {
		p.InjectedAt = record.InjectedAt.Format(time.RFC3339)
	}
	if moduleLoaded(p.PID, filepath.Base(m.dllPath)) {
		p.Injected = true
	}
}

func (m *Manager) refreshInjected() []Process {
	m.mu.Lock()
	records := make([]injectedRecord, 0, len(m.injected))
	for pid, record := range m.injected {
		records = append(records, record)
		_ = pid
	}
	m.mu.Unlock()

	out := make([]Process, 0, len(records))
	changed := false
	for _, record := range records {
		if !processAlive(record.PID) || !moduleLoaded(record.PID, filepath.Base(m.dllPath)) {
			m.mu.Lock()
			delete(m.injected, record.PID)
			m.mu.Unlock()
			changed = true
			continue
		}
		out = append(out, Process{
			PID:        record.PID,
			Name:       record.Name,
			Path:       record.Path,
			Injected:   true,
			InjectedAt: record.InjectedAt.Format(time.RFC3339),
			Message:    "Hook DLL 已加载",
		})
	}
	if changed {
		m.mu.Lock()
		m.saveInjectedLocked()
		m.mu.Unlock()
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PID < out[j].PID })
	return out
}

func (m *Manager) loadInjected() {
	data, err := os.ReadFile(m.injectedPath)
	if err != nil {
		return
	}
	var records []injectedRecord
	if err := json.Unmarshal(data, &records); err != nil {
		return
	}
	for _, record := range records {
		if record.PID > 0 {
			m.injected[record.PID] = record
		}
	}
}

func (m *Manager) saveInjectedLocked() {
	records := make([]injectedRecord, 0, len(m.injected))
	for _, record := range m.injected {
		records = append(records, record)
	}
	sort.Slice(records, func(i, j int) bool { return records[i].PID < records[j].PID })
	data, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return
	}
	if err := os.MkdirAll(m.configDir, 0o700); err != nil {
		return
	}
	_ = os.WriteFile(m.injectedPath, data, 0o600)
}

// prepare 生成 DLL 读取的 INI 配置。DLL 固定从 %APPDATA%\Scanning\hook 读取，
// 因此这里也写入该目录，确保自定义 data-dir 时仍能生效。
func (m *Manager) prepare() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.configOnce {
		return nil
	}
	if err := os.MkdirAll(m.configDir, 0o700); err != nil {
		return fmt.Errorf("创建 Hook 配置目录 %s: %w", m.configDir, err)
	}
	if _, err := os.Stat(m.dllPath); err != nil {
		m.dllExists = false
		return fmt.Errorf("Hook DLL 不可用（%s）: %w", m.dllPath, err)
	}
	m.dllExists = true

	ports := make([]string, 0, len(m.ports))
	for _, port := range m.ports {
		ports = append(ports, strconv.Itoa(port))
	}
	content := "[hook]\r\nproxy=" + m.proxyAddr + "\r\nports=" + strings.Join(ports, ",") + "\r\n"
	if err := writeUTF16File(filepath.Join(m.configDir, "scanning_hook.ini"), content); err != nil {
		return fmt.Errorf("写入 Hook 配置: %w", err)
	}
	m.configOnce = true
	return nil
}

func resolveDLL(configured string) (string, bool) {
	var candidates []string
	if strings.TrimSpace(configured) != "" {
		path := configured
		if !filepath.IsAbs(path) {
			if abs, err := filepath.Abs(path); err == nil {
				path = abs
			}
		}
		candidates = append(candidates, path)
	} else {
		var roots []string
		if exe, err := os.Executable(); err == nil {
			dir := filepath.Dir(exe)
			roots = append(roots, dir, filepath.Join(dir, "hook"))
		}
		if wd, err := os.Getwd(); err == nil {
			roots = append(roots, wd, filepath.Join(wd, "bin", "hook"), filepath.Join(wd, "hook"))
		}
		for _, root := range roots {
			candidates = append(candidates,
				filepath.Join(root, "scanning_hook_x64.dll"),
				filepath.Join(root, "scanning_hook.dll"),
			)
		}
		if appdata := os.Getenv("APPDATA"); appdata != "" {
			candidates = append(candidates, filepath.Join(appdata, "Scanning", "hook", "scanning_hook_x64.dll"))
		}
	}
	for _, path := range candidates {
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return path, true
		}
	}
	if len(candidates) > 0 {
		return candidates[0], false
	}
	return "", false
}

func hookConfigDir(dataDir string) string {
	if appdata := strings.TrimSpace(os.Getenv("APPDATA")); appdata != "" {
		return filepath.Join(appdata, "Scanning", "hook")
	}
	return filepath.Join(dataDir, "hook")
}

func normalizeProxyAddr(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "127.0.0.1:8899"
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	if host == "" {
		host = "127.0.0.1"
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsUnspecified() {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}

func normalizePorts(ports []int) []int {
	out := make([]int, 0, len(ports))
	seen := map[int]bool{}
	for _, port := range ports {
		if port > 0 && port <= 65535 && !seen[port] {
			seen[port] = true
			out = append(out, port)
		}
	}
	if len(out) == 0 {
		return []int{80, 443}
	}
	sort.Ints(out)
	return out
}

func writeUTF16File(path, content string) error {
	units := utf16.Encode([]rune(content))
	buf := make([]byte, 2+len(units)*2)
	buf[0] = 0xff
	buf[1] = 0xfe
	for i, unit := range units {
		buf[2+i*2] = byte(unit)
		buf[2+i*2+1] = byte(unit >> 8)
	}
	return os.WriteFile(path, buf, 0o600)
}
