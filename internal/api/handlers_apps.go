package api

import (
	"errors"
	"io"
	"log/slog"
	"net/http"
	"time"

	"scanning/internal/hook"
	"scanning/internal/launcher"
	"scanning/internal/procinfo"
)

type launchInjection struct {
	Attempted bool           `json:"attempted"`
	Injected  int            `json:"injected"`
	Failed    int            `json:"failed"`
	Message   string         `json:"message"`
	Results   []hook.Process `json:"results,omitempty"`
}

type launchAppResponse struct {
	*launcher.App
	Injection *launchInjection `json:"injection,omitempty"`
}

func (s *Server) handleListApps(w http.ResponseWriter, r *http.Request) {
	if s.launcher == nil {
		writeError(w, r, http.StatusServiceUnavailable, "LAUNCHER_UNAVAILABLE", "应用启动器未初始化", nil)
		return
	}
	writeData(w, r, s.launcher.List(), nil)
}

func (s *Server) handleRecentApps(w http.ResponseWriter, r *http.Request) {
	if s.launcher == nil {
		writeError(w, r, http.StatusServiceUnavailable, "LAUNCHER_UNAVAILABLE", "应用启动器未初始化", nil)
		return
	}
	writeData(w, r, s.launcher.Recent(), nil)
}

func (s *Server) handleGetApp(w http.ResponseWriter, r *http.Request) {
	if s.launcher == nil {
		writeError(w, r, http.StatusServiceUnavailable, "LAUNCHER_UNAVAILABLE", "应用启动器未初始化", nil)
		return
	}
	id := r.PathValue("id")
	app, ok := s.launcher.Get(id)
	if !ok {
		writeError(w, r, http.StatusNotFound, "APP_NOT_FOUND", "应用记录不存在", map[string]any{"id": id})
		return
	}
	writeData(w, r, app, nil)
}

func (s *Server) handleLaunchApp(w http.ResponseWriter, r *http.Request) {
	if s.launcher == nil {
		writeError(w, r, http.StatusServiceUnavailable, "LAUNCHER_UNAVAILABLE", "应用启动器未初始化", nil)
		return
	}
	if s.opts.Headless {
		writeError(w, r, http.StatusBadRequest, "HEADLESS_MODE", "无头模式不支持启动桌面应用", nil)
		return
	}
	if !isLoopbackRemote(r.RemoteAddr) {
		writeError(w, r, http.StatusForbidden, "LOCAL_ONLY", "启动桌面应用仅允许本机访问", nil)
		return
	}
	if s.proxy == nil || !s.proxy.Status().Running {
		writeError(w, r, http.StatusConflict, "PROXY_NOT_RUNNING", "请先启动代理，再启动桌面应用", nil)
		return
	}
	var req launcher.LaunchRequest
	if err := decodeJSON(w, r, &req); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, r, http.StatusBadRequest, "BAD_REQUEST", "请求体无效: "+err.Error(), nil)
		return
	}
	status := s.proxy.Status()
	if s.hook != nil {
		s.hook.SetProxyAddr(status.Addr)
	}
	app, err := s.launcher.Launch(status.Addr, req)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "APP_LAUNCH_FAILED", err.Error(), nil)
		return
	}
	response := launchAppResponse{App: app}
	if s.hook != nil && !req.SkipInject {
		response.Injection = s.autoInjectLaunchedApp(app.PID, app.Name)
	}
	writeData(w, r, response, nil)
}

// autoInjectLaunchedApp 在应用启动后立即注入主进程，并异步补齐同名子进程。
// 同步只做最关键的主进程注入，避免额外的固定等待阻塞启动请求；子进程注入在
// 响应返回后由后台完成，结果会通过 Hook 状态接口体现。
func (s *Server) autoInjectLaunchedApp(pid int, name string) *launchInjection {
	status := s.hook.Status()
	if !status.Supported {
		return nil
	}
	if !status.DLLExists {
		return &launchInjection{Message: "未找到 Hook DLL，已跳过自动注入"}
	}
	var results []hook.Process
	var lastErr error
	if pid > 0 {
		if first, err := s.hook.Inject(hook.InjectRequest{PID: pid}); err != nil {
			lastErr = err
		} else {
			results = append(results, first...)
		}
	}
	injection := &launchInjection{Attempted: true, Results: results}
	for _, result := range results {
		if result.Error != "" {
			injection.Failed++
		} else {
			injection.Injected++
		}
	}
	switch {
	case injection.Injected > 0:
		injection.Message = "已自动注入主进程，后台继续补齐同名子进程"
	case lastErr != nil:
		injection.Message = "主进程自动注入失败，后台继续尝试：" + lastErr.Error()
	default:
		injection.Message = "主进程未找到，后台继续尝试同名进程"
	}
	if name != "" {
		go s.injectSameNameLater(pid, name, time.Now())
	}
	return injection
}

const childInjectDelay = 600 * time.Millisecond

// injectSameNameLater 在启动响应返回后补注入同名子进程，不占用请求处理 goroutine。
// 只处理本次启动的进程和启动后创建的同名子进程，避免把旧实例也注入一遍。
func (s *Server) injectSameNameLater(launchedPID int, name string, started time.Time) {
	time.Sleep(childInjectDelay)
	procs := s.hook.ListProcesses(name)
	cutoff := started.Add(-5 * time.Second)
	targets := make([]hook.Process, 0, len(procs))
	for _, proc := range procs {
		if proc.PID == launchedPID {
			targets = append(targets, proc)
			continue
		}
		if created, ok := procinfo.ProcessStartTime(proc.PID); ok && !created.Before(cutoff) {
			targets = append(targets, proc)
		}
	}
	if len(targets) == 0 {
		return
	}

	injected := 0
	failed := 0
	for _, target := range targets {
		results, err := s.hook.Inject(hook.InjectRequest{PID: target.PID})
		if err != nil {
			failed++
			continue
		}
		for _, result := range results {
			if result.Error != "" {
				failed++
			} else {
				injected++
			}
		}
	}
	slog.Info("后台补注入 Hook 完成", "app", name, "injected", injected, "failed", failed)
}

func (s *Server) handlePickFile(w http.ResponseWriter, r *http.Request) {
	if s.opts.Headless {
		writeError(w, r, http.StatusBadRequest, "HEADLESS_MODE", "无头模式不支持打开文件对话框", nil)
		return
	}
	if !isLoopbackRemote(r.RemoteAddr) {
		writeError(w, r, http.StatusForbidden, "LOCAL_ONLY", "文件选择仅允许本机访问", nil)
		return
	}
	if !s.pickFileMu.TryLock() {
		writeError(w, r, http.StatusConflict, "PICK_FILE_BUSY", "已有一个文件选择框打开，请先完成或关闭它", nil)
		return
	}
	defer s.pickFileMu.Unlock()
	path, canceled, err := launcher.PickFile(r.Context())
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "PICK_FILE_FAILED", err.Error(), nil)
		return
	}
	writeData(w, r, map[string]any{
		"path":     path,
		"canceled": canceled,
	}, nil)
}
