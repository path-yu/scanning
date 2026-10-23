package api

import (
	"errors"
	"io"
	"net/http"

	"scanning/internal/launcher"
)

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
	app, err := s.launcher.Launch(status.Addr, req)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "APP_LAUNCH_FAILED", err.Error(), nil)
		return
	}
	writeData(w, r, app, nil)
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
