package api

import (
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"

	"scanning/internal/hook"
	"scanning/internal/proxy"
)

func (s *Server) hookReady(w http.ResponseWriter, r *http.Request) bool {
	if s.hook == nil {
		writeError(w, r, http.StatusServiceUnavailable, "HOOK_UNAVAILABLE", "进程注入管理器未初始化", nil)
		return false
	}
	if !isLoopbackRemote(r.RemoteAddr) {
		writeError(w, r, http.StatusForbidden, "LOCAL_ONLY", "进程注入仅允许本机访问", nil)
		return false
	}
	if s.proxy != nil {
		if status := s.proxy.Status(); status.Running {
			s.hook.SetProxyAddr(status.Addr)
		}
	}
	return true
}

func (s *Server) handleHookStatus(w http.ResponseWriter, r *http.Request) {
	if !s.hookReady(w, r) {
		return
	}
	writeData(w, r, s.hook.Status(), nil)
}

func (s *Server) handleHookProcesses(w http.ResponseWriter, r *http.Request) {
	if !s.hookReady(w, r) {
		return
	}
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		writeError(w, r, http.StatusBadRequest, "BAD_REQUEST", "缺少进程名 name", nil)
		return
	}
	writeData(w, r, s.hook.ListProcesses(name), nil)
}

func (s *Server) handleHookInject(w http.ResponseWriter, r *http.Request) {
	if !s.hookReady(w, r) {
		return
	}
	if s.opts.Headless {
		writeError(w, r, http.StatusBadRequest, "HEADLESS_MODE", "无头模式不支持注入桌面应用", nil)
		return
	}
	status := proxy.Status{}
	if s.proxy != nil {
		status = s.proxy.Status()
	}
	if !status.Running {
		writeError(w, r, http.StatusConflict, "PROXY_NOT_RUNNING", "请先启动代理，再注入目标进程", nil)
		return
	}
	var req hook.InjectRequest
	if err := decodeJSON(w, r, &req); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, r, http.StatusBadRequest, "BAD_REQUEST", "请求体无效: "+err.Error(), nil)
		return
	}
	if req.PID <= 0 && strings.TrimSpace(req.Name) == "" {
		writeError(w, r, http.StatusBadRequest, "BAD_REQUEST", "请提供 pid 或 name", nil)
		return
	}
	results, err := s.hook.Inject(req)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "HOOK_INJECT_FAILED", err.Error(), nil)
		return
	}
	failed := 0
	for _, result := range results {
		if result.Error != "" {
			failed++
		}
	}
	if failed == len(results) && failed > 0 {
		writeError(w, r, http.StatusBadGateway, "HOOK_INJECT_FAILED", "所有目标进程注入失败", results)
		return
	}
	writeData(w, r, map[string]any{
		"results": results,
		"status":  s.hook.Status(),
	}, nil)
}

func (s *Server) handleHookLog(w http.ResponseWriter, r *http.Request) {
	if !s.hookReady(w, r) {
		return
	}
	status := s.hook.Status()
	limit := 200
	if raw := r.URL.Query().Get("lines"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 && n <= 2000 {
			limit = n
		}
	}
	text := ""
	if status.LogPath != "" {
		if data, err := os.ReadFile(status.LogPath); err == nil {
			lines := strings.Split(strings.TrimRight(string(data), "\r\n"), "\n")
			if len(lines) > limit {
				lines = lines[len(lines)-limit:]
			}
			text = strings.Join(lines, "\n")
		}
	}
	writeData(w, r, map[string]any{
		"path": status.LogPath,
		"text": text,
	}, nil)
}
