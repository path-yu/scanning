package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"scanning/internal/blob"
	harexport "scanning/internal/export"
	"scanning/internal/flow"
)

func (s *Server) handleProxyStatus(w http.ResponseWriter, r *http.Request) {
	if s.proxy == nil {
		writeError(w, r, http.StatusServiceUnavailable, "PROXY_UNAVAILABLE", "代理引擎未初始化", nil)
		return
	}
	writeData(w, r, s.proxy.Status(), nil)
}

func (s *Server) handleProxyStart(w http.ResponseWriter, r *http.Request) {
	if s.proxy == nil {
		writeError(w, r, http.StatusServiceUnavailable, "PROXY_UNAVAILABLE", "代理引擎未初始化", nil)
		return
	}
	if err := s.proxy.Start(); err != nil {
		writeError(w, r, http.StatusBadGateway, "PROXY_START_FAILED", err.Error(), nil)
		return
	}
	status := s.proxy.Status()
	if s.hook != nil {
		s.hook.SetProxyAddr(status.Addr)
	}
	s.hub.Broadcast("proxy.status", status)
	writeData(w, r, status, nil)
}

func (s *Server) handleProxyStop(w http.ResponseWriter, r *http.Request) {
	if s.proxy == nil {
		writeError(w, r, http.StatusServiceUnavailable, "PROXY_UNAVAILABLE", "代理引擎未初始化", nil)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if err := s.proxy.Stop(ctx); err != nil {
		writeError(w, r, http.StatusInternalServerError, "PROXY_STOP_FAILED", err.Error(), nil)
		return
	}
	status := s.proxy.Status()
	s.hub.Broadcast("proxy.status", status)
	writeData(w, r, status, nil)
}

func (s *Server) handleCertStatus(w http.ResponseWriter, r *http.Request) {
	if s.certs == nil {
		writeError(w, r, http.StatusServiceUnavailable, "CERT_NOT_READY", "证书中心未初始化", nil)
		return
	}
	writeData(w, r, s.certs.Status(), nil)
}

func (s *Server) handleCertDownload(w http.ResponseWriter, r *http.Request) {
	if s.certs == nil {
		writeError(w, r, http.StatusServiceUnavailable, "CERT_NOT_READY", "证书中心未初始化", nil)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="scanning-ca.pem"`)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(s.certs.CAPEM())
}

func (s *Server) handleCertInstall(w http.ResponseWriter, r *http.Request) {
	if s.certs == nil {
		writeError(w, r, http.StatusServiceUnavailable, "CERT_NOT_READY", "证书中心未初始化", nil)
		return
	}
	var req struct {
		Target string `json:"target"`
	}
	if err := decodeJSON(w, r, &req); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, r, http.StatusBadRequest, "BAD_REQUEST", "请求体无效: "+err.Error(), nil)
		return
	}
	result, err := s.certs.Install(r.Context(), req.Target)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "CERT_INSTALL_FAILED", err.Error(), nil)
		return
	}
	s.hub.Broadcast("cert.status", result.Status)
	writeData(w, r, result, nil)
}

func (s *Server) handleCertRegenerate(w http.ResponseWriter, r *http.Request) {
	if s.certs == nil {
		writeError(w, r, http.StatusServiceUnavailable, "CERT_NOT_READY", "证书中心未初始化", nil)
		return
	}
	var req struct {
		Confirm bool `json:"confirm"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, r, http.StatusBadRequest, "BAD_REQUEST", "请求体无效: "+err.Error(), nil)
		return
	}
	if !req.Confirm {
		writeError(w, r, http.StatusBadRequest, "BAD_REQUEST", "重新生成根证书需要 confirm=true", nil)
		return
	}
	if err := s.certs.Rotate(); err != nil {
		writeError(w, r, http.StatusInternalServerError, "CERT_REGENERATE_FAILED", err.Error(), nil)
		return
	}
	status := s.certs.Status()
	s.hub.Broadcast("cert.changed", status)
	writeData(w, r, map[string]any{
		"status":  status,
		"message": "根证书已重新生成，旧证书立即失效；请重新安装 CA 并重启相关客户端。",
	}, nil)
}

func (s *Server) handleExportHAR(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if sid := q.Get("sessionId"); sid != "" && sid != s.opts.Session.ID {
		writeError(w, r, http.StatusNotFound, "SESSION_NOT_FOUND", "会话不存在", map[string]any{"sessionId": sid})
		return
	}
	pred, err := flow.CompileFilter(q.Get("filter"))
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "BAD_REQUEST", err.Error(), nil)
		return
	}

	all := s.store.All()
	flows := make([]*flow.Flow, 0, len(all))
	for _, f := range all {
		if pred(f) {
			flows = append(flows, f)
		}
	}

	filename := fmt.Sprintf("scanning-%s.har", time.Now().Format("20060102-150405"))
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Scanning-Flow-Count", fmt.Sprintf("%d", len(flows)))

	loader := func(body *flow.Body) []byte {
		if s.blobs == nil || body == nil || body.Ref == "" {
			return nil
		}
		data, err := s.blobs.Get(body.Ref)
		if err != nil {
			return nil
		}
		if decoded, ok := blob.Decode(data, body.Encoding); ok {
			return decoded
		}
		return nil
	}
	if err := harexport.WriteWithBodies(w, flows, versionString(), loader); err != nil {
		slog.Error("导出 HAR 失败", "error", err)
	}
}
