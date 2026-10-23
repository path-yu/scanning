// Package launcher 启动桌面应用并注入指向本机代理的环境变量。
package launcher

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/oklog/ulid/v2"

	"scanning/internal/procinfo"
)

const (
	StatusRunning = "running"
	StatusExited  = "exited"
	StatusFailed  = "failed"

	maxApps      = 30
	maxRecent    = 10
	maxArgs      = 64
	maxArgLen    = 4096
	maxPathLen   = 4096
	recentFile   = "recent-apps.json"
	proxyNoProxy = "127.0.0.1,localhost,::1"
)

type LaunchRequest struct {
	Path          string            `json:"path"`
	Args          []string          `json:"args,omitempty"`
	Cwd           string            `json:"cwd,omitempty"`
	Env           map[string]string `json:"env,omitempty"`
	ChromiumFlags bool              `json:"chromiumFlags,omitempty"`
	LogOutput     bool              `json:"logOutput,omitempty"`
}

type App struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Path      string     `json:"path"`
	Args      []string   `json:"args,omitempty"`
	Cwd       string     `json:"cwd,omitempty"`
	PID       int        `json:"pid"`
	Status    string     `json:"status"`
	ExitCode  int        `json:"exitCode,omitempty"`
	StartedAt time.Time  `json:"startedAt"`
	EndedAt   *time.Time `json:"endedAt,omitempty"`
	LogPath   string     `json:"logPath,omitempty"`
	Error     string     `json:"error,omitempty"`
	Diagnosis *Diagnosis `json:"diagnosis,omitempty"`
}

type Endpoint struct {
	Address string `json:"address"`
	Port    int    `json:"port"`
	Count   int    `json:"count"`
}

type Diagnosis struct {
	Status    string     `json:"status"` // checking | proxy | direct | unknown
	CheckedAt time.Time  `json:"checkedAt"`
	Flows     int        `json:"flows,omitempty"`
	Proxied   int        `json:"proxied,omitempty"`
	Direct    []Endpoint `json:"direct,omitempty"`
	Message   string     `json:"message"`
}

type Recent struct {
	Name           string    `json:"name"`
	Path           string    `json:"path"`
	Args           []string  `json:"args,omitempty"`
	Cwd            string    `json:"cwd,omitempty"`
	LastLaunchedAt time.Time `json:"lastLaunchedAt"`
}

type Manager struct {
	mu              sync.Mutex
	dataDir         string
	recentPath      string
	apps            map[string]*App
	order           []string
	recent          []Recent
	flowCounter     func(appName string, pid int, since time.Time) int
	startupInjector func(pid int) error
}

func NewManager(dataDir string) *Manager {
	m := &Manager{
		dataDir:    dataDir,
		recentPath: filepath.Join(dataDir, recentFile),
		apps:       make(map[string]*App),
	}
	m.loadRecent()
	return m
}

// SetFlowCounter 注入 Flow 统计函数，用于判断启动后是否真的经代理产生了请求。
func (m *Manager) SetFlowCounter(fn func(appName string, pid int, since time.Time) int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.flowCounter = fn
}

// SetStartupInjector 设置应用启动前的 Hook 注入函数。
// Windows 下应用会以挂起状态创建，注入完成后再恢复主线程，避免应用先建立直连。
func (m *Manager) SetStartupInjector(fn func(pid int) error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.startupInjector = fn
}

func callStartupInjector(fn func(int) error, pid int) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("启动前注入 Hook 时 panic: %v", r)
		}
	}()
	return fn(pid)
}

// Launch 以子进程方式启动应用，并注入 HTTP(S)_PROXY 环境变量。
func (m *Manager) Launch(proxyAddr string, req LaunchRequest) (*App, error) {
	proxyAddr = strings.TrimSpace(proxyAddr)
	if proxyAddr == "" {
		return nil, errors.New("代理地址为空，请先启动代理")
	}
	executable, err := validateExecutable(req.Path)
	if err != nil {
		return nil, err
	}
	if len(req.Args) > maxArgs {
		return nil, fmt.Errorf("启动参数最多 %d 个", maxArgs)
	}
	for _, arg := range req.Args {
		if len(arg) > maxArgLen {
			return nil, fmt.Errorf("单个启动参数不能超过 %d 字符", maxArgLen)
		}
		if strings.ContainsRune(arg, 0) {
			return nil, errors.New("启动参数包含非法字符")
		}
	}
	cwd := strings.TrimSpace(req.Cwd)
	if cwd != "" {
		abs, err := filepath.Abs(cwd)
		if err != nil {
			return nil, fmt.Errorf("工作目录无效: %w", err)
		}
		info, err := os.Stat(abs)
		if err != nil || !info.IsDir() {
			return nil, fmt.Errorf("工作目录不存在: %s", abs)
		}
		cwd = abs
	}
	extraEnv, err := normalizeEnv(req.Env)
	if err != nil {
		return nil, err
	}

	args := append([]string(nil), req.Args...)
	if req.ChromiumFlags {
		args = append([]string{"--proxy-server=http://" + proxyAddr}, args...)
	}
	m.mu.Lock()
	injector := m.startupInjector
	m.mu.Unlock()
	suspended := injector != nil && suspendedStartSupported

	cmd := exec.Command(executable, args...)
	cmd.Dir = cwd
	cmd.Env = BuildEnv(proxyAddr, extraEnv)
	if suspended {
		configureSuspended(cmd)
	}

	var logFile *os.File
	logPath := ""
	if req.LogOutput {
		dir := filepath.Join(m.dataDir, "logs", "apps")
		if err := os.MkdirAll(dir, 0o700); err == nil {
			path := filepath.Join(dir, time.Now().Format("20060102-150405")+"-"+ulid.Make().String()+".log")
			if file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600); err == nil {
				logFile = file
				logPath = path
				cmd.Stdout = file
				cmd.Stderr = file
			} else {
				slog.Warn("创建应用日志失败", "error", err)
			}
		}
	}

	if err := cmd.Start(); err != nil {
		if logFile != nil {
			_ = logFile.Close()
		}
		return nil, fmt.Errorf("启动应用失败: %w", err)
	}

	if suspended {
		pid := cmd.Process.Pid
		if injectErr := callStartupInjector(injector, pid); injectErr != nil {
			slog.Warn("启动前注入 Hook 失败，应用将以直连方式启动", "pid", pid, "error", injectErr)
		}
		if resumeErr := resumeProcess(pid); resumeErr != nil {
			_ = cmd.Process.Kill()
			if logFile != nil {
				_ = logFile.Close()
			}
			return nil, fmt.Errorf("恢复应用主线程失败: %w", resumeErr)
		}
	}

	now := time.Now()
	app := &App{
		ID:        ulid.Make().String(),
		Name:      filepath.Base(executable),
		Path:      executable,
		Args:      append([]string(nil), req.Args...),
		Cwd:       cwd,
		PID:       cmd.Process.Pid,
		Status:    StatusRunning,
		StartedAt: now,
		LogPath:   logPath,
		Diagnosis: &Diagnosis{
			Status:    "checking",
			CheckedAt: now,
			Message:   "正在检测代理使用情况…",
		},
	}

	m.mu.Lock()
	m.apps[app.ID] = app
	m.order = append(m.order, app.ID)
	m.pruneLocked()
	m.upsertRecentLocked(app, now)
	clone := cloneApp(app)
	m.mu.Unlock()

	slog.Info("已启动桌面应用", "name", app.Name, "pid", app.PID, "proxy", proxyAddr)
	go m.wait(app.ID, cmd, logFile)
	go m.diagnose(app.ID, executable, proxyAddr, now)

	return clone, nil
}

func (m *Manager) wait(id string, cmd *exec.Cmd, logFile *os.File) {
	err := cmd.Wait()
	if logFile != nil {
		_ = logFile.Close()
	}
	now := time.Now()

	m.mu.Lock()
	defer m.mu.Unlock()
	app := m.apps[id]
	if app == nil {
		return
	}
	app.EndedAt = &now
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			app.Status = StatusExited
			app.ExitCode = exitErr.ExitCode()
		} else {
			app.Status = StatusFailed
			app.Error = err.Error()
		}
	} else {
		app.Status = StatusExited
	}
}

func (m *Manager) diagnose(id, executable, proxyAddr string, started time.Time) {
	time.Sleep(6 * time.Second)
	for attempt := 0; attempt < 2; attempt++ {
		diag := m.checkTraffic(id, executable, proxyAddr, started)
		if diag == nil {
			return
		}
		m.mu.Lock()
		if app := m.apps[id]; app != nil {
			app.Diagnosis = diag
		}
		m.mu.Unlock()
		// 自动注入 Hook 后，启动初期的直连连接可能仍然存在；再观察一轮，
		// 等经代理的 Flow 产生后把状态纠正为 proxy。
		if (diag.Status != "unknown" && diag.Status != "direct") || attempt == 1 {
			return
		}
		time.Sleep(6 * time.Second)
	}
}

func (m *Manager) checkTraffic(id, executable, proxyAddr string, started time.Time) *Diagnosis {
	m.mu.Lock()
	app := m.apps[id]
	if app == nil {
		m.mu.Unlock()
		return nil
	}
	name, pid := app.Name, app.PID
	counter := m.flowCounter
	m.mu.Unlock()

	pids := procinfo.ProcessIDsByPath(executable)
	if pid > 0 && !containsInt(pids, pid) {
		pids = append(pids, pid)
	}

	flows := 0
	if counter != nil {
		flows = counter(name, pid, started)
	}
	proxyPort := portOf(proxyAddr)
	proxied := 0
	direct := make(map[string]int)
	for _, conn := range procinfo.ConnectionsForPIDs(pids) {
		if conn.State != "ESTABLISHED" {
			continue
		}
		if conn.RemotePort == proxyPort && isLoopbackIP(conn.RemoteIP) {
			proxied++
			continue
		}
		if !isLoopbackIP(conn.RemoteIP) && conn.RemotePort > 0 {
			direct[net.JoinHostPort(conn.RemoteIP, strconv.Itoa(conn.RemotePort))]++
		}
	}
	return buildDiagnosis(flows, proxied, direct, proxyAddr)
}

func buildDiagnosis(flows, proxied int, direct map[string]int, proxyAddr string) *Diagnosis {
	diag := &Diagnosis{
		Status:    "unknown",
		CheckedAt: time.Now(),
		Flows:     flows,
		Proxied:   proxied,
	}
	switch {
	case flows > 0:
		diag.Status = "proxy"
		diag.Message = fmt.Sprintf("已捕获 %d 条经 %s 的请求", flows, proxyAddr)
	case proxied > 0:
		diag.Status = "proxy"
		diag.Message = fmt.Sprintf("检测到 %d 条连接指向代理 %s", proxied, proxyAddr)
	case len(direct) > 0:
		diag.Status = "direct"
		diag.Direct = topEndpoints(direct, 5)
		diag.Message = fmt.Sprintf("未检测到经 %s 的请求，检测到直连目标（该应用可能忽略环境变量代理）", proxyAddr)
	default:
		diag.Message = "未检测到该应用的网络连接（可能尚未发起请求、进程已退出或使用非 TCP 协议）"
	}
	return diag
}

func topEndpoints(direct map[string]int, limit int) []Endpoint {
	items := make([]Endpoint, 0, len(direct))
	for key, count := range direct {
		host, portText, err := net.SplitHostPort(key)
		if err != nil {
			continue
		}
		port, err := strconv.Atoi(portText)
		if err != nil {
			continue
		}
		items = append(items, Endpoint{Address: host, Port: port, Count: count})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Count == items[j].Count {
			return items[i].Address < items[j].Address
		}
		return items[i].Count > items[j].Count
	})
	if len(items) > limit {
		items = items[:limit]
	}
	return items
}

func portOf(addr string) int {
	_, portText, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return 0
	}
	return port
}

func isLoopbackIP(value string) bool {
	ip := net.ParseIP(value)
	return ip != nil && ip.IsLoopback()
}

func containsInt(items []int, target int) bool {
	for _, item := range items {
		if item == target {
			return true
		}
	}
	return false
}

func (m *Manager) List() []*App {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*App, 0, len(m.order))
	for i := len(m.order) - 1; i >= 0; i-- {
		if app := m.apps[m.order[i]]; app != nil {
			out = append(out, cloneApp(app))
		}
	}
	return out
}

func (m *Manager) Get(id string) (*App, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	app, ok := m.apps[id]
	if !ok {
		return nil, false
	}
	return cloneApp(app), true
}

func (m *Manager) Recent() []Recent {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Recent, len(m.recent))
	copy(out, m.recent)
	return out
}

func (m *Manager) pruneLocked() {
	if len(m.order) <= maxApps {
		return
	}
	keep := make([]string, 0, maxApps)
	removed := len(m.order) - maxApps
	for _, id := range m.order {
		app := m.apps[id]
		if removed > 0 && app != nil && app.Status != StatusRunning {
			delete(m.apps, id)
			removed--
			continue
		}
		keep = append(keep, id)
	}
	m.order = keep
}

func (m *Manager) upsertRecentLocked(app *App, at time.Time) {
	for i := range m.recent {
		if strings.EqualFold(m.recent[i].Path, app.Path) {
			m.recent[i].Args = append([]string(nil), app.Args...)
			m.recent[i].Cwd = app.Cwd
			m.recent[i].LastLaunchedAt = at
			if i > 0 {
				item := m.recent[i]
				m.recent = append(m.recent[:i], m.recent[i+1:]...)
				m.recent = append([]Recent{item}, m.recent...)
			}
			m.saveRecentLocked()
			return
		}
	}
	m.recent = append([]Recent{{
		Name:           app.Name,
		Path:           app.Path,
		Args:           append([]string(nil), app.Args...),
		Cwd:            app.Cwd,
		LastLaunchedAt: at,
	}}, m.recent...)
	if len(m.recent) > maxRecent {
		m.recent = m.recent[:maxRecent]
	}
	m.saveRecentLocked()
}

func (m *Manager) loadRecent() {
	data, err := os.ReadFile(m.recentPath)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			slog.Warn("读取最近应用失败", "error", err)
		}
		return
	}
	var items []Recent
	if err := json.Unmarshal(data, &items); err != nil {
		slog.Warn("解析最近应用失败", "error", err)
		return
	}
	if len(items) > maxRecent {
		items = items[:maxRecent]
	}
	m.recent = items
}

func (m *Manager) saveRecentLocked() {
	data, err := json.MarshalIndent(m.recent, "", "  ")
	if err != nil {
		slog.Warn("序列化最近应用失败", "error", err)
		return
	}
	tmp := m.recentPath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		slog.Warn("写入最近应用失败", "error", err)
		return
	}
	if err := os.Rename(tmp, m.recentPath); err != nil {
		slog.Warn("替换最近应用文件失败", "error", err)
	}
}

// BuildEnv 在继承当前进程环境的基础上，强制覆盖代理变量。
func BuildEnv(proxyAddr string, extra map[string]string) []string {
	proxyURL := "http://" + proxyAddr
	skip := map[string]bool{
		"http_proxy":  true,
		"https_proxy": true,
		"all_proxy":   true,
		"no_proxy":    true,
	}
	out := make([]string, 0, len(os.Environ())+5+len(extra))
	for _, item := range os.Environ() {
		key := item
		if idx := strings.IndexByte(item, '='); idx >= 0 {
			key = item[:idx]
		}
		if skip[strings.ToLower(key)] {
			continue
		}
		out = append(out, item)
	}
	out = append(out,
		"HTTP_PROXY="+proxyURL,
		"HTTPS_PROXY="+proxyURL,
		"http_proxy="+proxyURL,
		"https_proxy="+proxyURL,
		"NO_PROXY="+proxyNoProxy,
		"no_proxy="+proxyNoProxy,
	)
	keys := make([]string, 0, len(extra))
	for key := range extra {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		out = append(out, key+"="+extra[key])
	}
	return out
}

func validateExecutable(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", errors.New("请选择要启动的应用")
	}
	if len(path) > maxPathLen {
		return "", errors.New("应用路径过长")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("应用路径无效: %w", err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", fmt.Errorf("应用不存在: %s", abs)
	}
	if info.IsDir() {
		return "", errors.New("请选择可执行文件而不是目录")
	}
	if runtime.GOOS == "windows" {
		switch strings.ToLower(filepath.Ext(abs)) {
		case ".exe", ".com":
		default:
			return "", errors.New("Windows 下仅支持 .exe/.com 可执行文件（不支持批处理或脚本）")
		}
	} else if info.Mode()&0o111 == 0 {
		return "", errors.New("该文件没有执行权限")
	}
	return abs, nil
}

func normalizeEnv(extra map[string]string) (map[string]string, error) {
	if len(extra) == 0 {
		return nil, nil
	}
	if len(extra) > 32 {
		return nil, errors.New("附加环境变量最多 32 个")
	}
	out := make(map[string]string, len(extra))
	for key, value := range extra {
		if key == "" || strings.ContainsAny(key, "=\x00") {
			return nil, fmt.Errorf("环境变量名无效: %q", key)
		}
		if strings.ContainsRune(value, 0) {
			return nil, fmt.Errorf("环境变量 %s 的值包含非法字符", key)
		}
		out[key] = value
	}
	return out, nil
}

func cloneApp(app *App) *App {
	if app == nil {
		return nil
	}
	clone := *app
	clone.Args = append([]string(nil), app.Args...)
	if app.Diagnosis != nil {
		diag := *app.Diagnosis
		diag.Direct = append([]Endpoint(nil), app.Diagnosis.Direct...)
		clone.Diagnosis = &diag
	}
	return &clone
}
