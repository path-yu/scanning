package api

import (
	"errors"
	"io"
	"net/http"

	"scanning/internal/browser"
)

func (s *Server) handleLaunchBrowser(w http.ResponseWriter, r *http.Request) {
	if s.proxy == nil {
		writeError(w, r, http.StatusServiceUnavailable, "PROXY_UNAVAILABLE", "代理引擎未初始化", nil)
		return
	}
	if s.opts.Headless {
		writeError(w, r, http.StatusBadRequest, "HEADLESS_MODE", "无头模式不支持启动浏览器", nil)
		return
	}
	if !isLoopbackRemote(r.RemoteAddr) {
		writeError(w, r, http.StatusForbidden, "LOCAL_ONLY", "启动浏览器仅允许本机访问", nil)
		return
	}
	var req struct {
		URL     string `json:"url"`
		Browser string `json:"browser"`
	}
	if err := decodeJSON(w, r, &req); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, r, http.StatusBadRequest, "BAD_REQUEST", "请求体无效: "+err.Error(), nil)
		return
	}
	status := s.proxy.Status()
	if !status.Running {
		writeError(w, r, http.StatusConflict, "PROXY_NOT_RUNNING", "请先启动代理，再打开抓包浏览器", nil)
		return
	}
	result, err := browser.Launch(browser.Options{
		ProxyAddr: status.Addr,
		DataDir:   s.opts.DataDir,
		URL:       req.URL,
		Preferred: req.Browser,
	})
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "BROWSER_LAUNCH_FAILED", err.Error(), nil)
		return
	}
	writeData(w, r, result, nil)
}
