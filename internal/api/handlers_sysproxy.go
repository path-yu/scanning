package api

import (
	"net/http"
)

func (s *Server) handleSystemProxyStatus(w http.ResponseWriter, r *http.Request) {
	if s.sysProxy == nil {
		writeError(w, r, http.StatusServiceUnavailable, "SYSPROXY_UNAVAILABLE", "系统代理管理器未初始化", nil)
		return
	}
	status, err := s.sysProxy.Status()
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "SYSPROXY_STATUS_FAILED", err.Error(), nil)
		return
	}
	writeData(w, r, status, nil)
}

func (s *Server) handleSystemProxyApply(w http.ResponseWriter, r *http.Request) {
	if s.sysProxy == nil {
		writeError(w, r, http.StatusServiceUnavailable, "SYSPROXY_UNAVAILABLE", "系统代理管理器未初始化", nil)
		return
	}
	if !isLoopbackRemote(r.RemoteAddr) {
		writeError(w, r, http.StatusForbidden, "LOCAL_ONLY", "接管系统代理仅允许本机访问", nil)
		return
	}
	if s.proxy == nil || !s.proxy.Status().Running {
		writeError(w, r, http.StatusConflict, "PROXY_NOT_RUNNING", "请先启动代理，再接管系统代理", nil)
		return
	}
	status, err := s.sysProxy.Apply(s.proxy.Status().Addr)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "SYSPROXY_APPLY_FAILED", err.Error(), nil)
		return
	}
	writeData(w, r, status, nil)
}

func (s *Server) handleSystemProxyRestore(w http.ResponseWriter, r *http.Request) {
	if s.sysProxy == nil {
		writeError(w, r, http.StatusServiceUnavailable, "SYSPROXY_UNAVAILABLE", "系统代理管理器未初始化", nil)
		return
	}
	if !isLoopbackRemote(r.RemoteAddr) {
		writeError(w, r, http.StatusForbidden, "LOCAL_ONLY", "还原系统代理仅允许本机访问", nil)
		return
	}
	status, err := s.sysProxy.Restore()
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "SYSPROXY_RESTORE_FAILED", err.Error(), nil)
		return
	}
	writeData(w, r, status, nil)
}
