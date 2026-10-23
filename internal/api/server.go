package api

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/oklog/ulid/v2"

	"scanning/internal/blob"
	"scanning/internal/capture"
	"scanning/internal/config"
	"scanning/internal/event"
	"scanning/internal/flow"
	"scanning/internal/hook"
	"scanning/internal/launcher"
	"scanning/internal/mitm"
	"scanning/internal/persist"
	"scanning/internal/proxy"
	"scanning/internal/rules"
	"scanning/internal/store"
	"scanning/internal/sysproxy"
	"scanning/internal/version"
	"scanning/web"
)

const (
	sessionCookieName = "scanning_session"
	ctxKeyRequestID   = ctxKey("request_id")
	ctxKeyAuthMethod  = ctxKey("auth_method")
)

type ctxKey string

type authMethod string

const (
	authDev    authMethod = "dev"
	authBearer authMethod = "bearer"
	authCookie authMethod = "cookie"
)

type Options struct {
	Config   config.Config
	Store    *store.Ring
	Hub      *event.Hub
	Proxy    *proxy.Engine
	Certs    *mitm.Center
	Blobs    *blob.Store
	Rules    *rules.Store
	Capture  *capture.Engine
	DB       *persist.DB
	Launcher *launcher.Manager
	Hook     *hook.Manager
	SysProxy *sysproxy.Manager
	Token    string
	Session  flow.Session
	DataDir  string
	Dev      bool
	Headless bool
}

type Server struct {
	opts      Options
	store     *store.Ring
	hub       *event.Hub
	proxy     *proxy.Engine
	certs     *mitm.Center
	blobs     *blob.Store
	rules     *rules.Store
	capture   *capture.Engine
	db        *persist.DB
	launcher  *launcher.Manager
	hook      *hook.Manager
	sysProxy  *sysproxy.Manager
	webFS     fs.FS // 仅在非 dev 构建中初始化
	startedAt time.Time

	requestCount atomic.Int64
	statsMu      sync.Mutex
	lastCount    int64
	lastStatsAt  time.Time
	qps          float64
}

func New(opts Options) *Server {
	s := &Server{
		opts:        opts,
		store:       opts.Store,
		hub:         opts.Hub,
		proxy:       opts.Proxy,
		certs:       opts.Certs,
		blobs:       opts.Blobs,
		rules:       opts.Rules,
		capture:     opts.Capture,
		db:          opts.DB,
		launcher:    opts.Launcher,
		hook:        opts.Hook,
		sysProxy:    opts.SysProxy,
		startedAt:   time.Now(),
		lastStatsAt: time.Now(),
	}
	if !web.Dev {
		if sub, err := fs.Sub(web.Assets, "dist"); err != nil {
			slog.Warn("前端静态资源不可用", "error", err)
		} else {
			s.webFS = sub
		}
	}
	return s
}

func (s *Server) Handler() http.Handler {
	apiMux := http.NewServeMux()
	apiMux.HandleFunc("GET /api/v1/health", s.handleHealth)
	apiMux.HandleFunc("GET /api/v1/system/info", s.handleSystemInfo)
	apiMux.HandleFunc("POST /api/v1/system/selftest", s.handleSelfTest)
	apiMux.HandleFunc("GET /api/v1/stats", s.handleStats)
	apiMux.HandleFunc("GET /api/v1/sessions", s.handleSessions)
	apiMux.HandleFunc("POST /api/v1/sessions", s.handleSaveSession)
	apiMux.HandleFunc("POST /api/v1/sessions/{id}/load", s.handleLoadSession)
	apiMux.HandleFunc("DELETE /api/v1/sessions/{id}", s.handleDeleteSession)
	apiMux.HandleFunc("GET /api/v1/flows", s.handleListFlows)
	apiMux.HandleFunc("GET /api/v1/flows/search", s.handleSearchFlows)
	apiMux.HandleFunc("GET /api/v1/flows/{id}", s.handleGetFlow)
	apiMux.HandleFunc("PATCH /api/v1/flows/{id}", s.handlePatchFlow)
	apiMux.HandleFunc("GET /api/v1/flows/{id}/body", s.handleFlowBody)
	apiMux.HandleFunc("POST /api/v1/flows/{id}/replay", s.handleReplayFlow)
	apiMux.HandleFunc("POST /api/v1/flows/{id}/resume", s.handleResumeFlow)
	apiMux.HandleFunc("GET /api/v1/breakpoints", s.handleBreakpoints)
	apiMux.HandleFunc("DELETE /api/v1/flows", s.handleDeleteFlows)
	apiMux.HandleFunc("GET /api/v1/domains", s.handleDomains)
	apiMux.HandleFunc("POST /api/v1/demo/flows", s.handleDemoFlows)
	apiMux.HandleFunc("GET /api/v1/rules", s.handleListRules)
	apiMux.HandleFunc("POST /api/v1/rules", s.handleSaveRule)
	apiMux.HandleFunc("PUT /api/v1/rules/{id}", s.handleUpdateRule)
	apiMux.HandleFunc("DELETE /api/v1/rules/{id}", s.handleDeleteRule)

	apiMux.HandleFunc("GET /api/v1/interfaces", s.handleInterfaces)
	apiMux.HandleFunc("GET /api/v1/capture/status", s.handleCaptureStatus)
	apiMux.HandleFunc("POST /api/v1/capture/start", s.handleCaptureStart)
	apiMux.HandleFunc("POST /api/v1/capture/stop", s.handleCaptureStop)
	apiMux.HandleFunc("POST /api/v1/capture/mirror", s.handleCaptureMirror)
	apiMux.HandleFunc("POST /api/v1/capture/import", s.handleCaptureImport)
	apiMux.HandleFunc("GET /api/v1/packets", s.handleListPackets)
	apiMux.HandleFunc("GET /api/v1/packets/{id}", s.handleGetPacket)
	apiMux.HandleFunc("DELETE /api/v1/packets", s.handleClearPackets)
	apiMux.HandleFunc("GET /api/v1/dns", s.handleDNS)
	apiMux.HandleFunc("GET /api/v1/export/pcap", s.handleExportPCAP)
	apiMux.HandleFunc("GET /api/v1/events", s.handleEvents)

	apiMux.HandleFunc("GET /api/v1/proxy/status", s.handleProxyStatus)
	apiMux.HandleFunc("POST /api/v1/proxy/start", s.handleProxyStart)
	apiMux.HandleFunc("POST /api/v1/proxy/stop", s.handleProxyStop)
	apiMux.HandleFunc("POST /api/v1/browser/launch", s.handleLaunchBrowser)
	apiMux.HandleFunc("GET /api/v1/apps", s.handleListApps)
	apiMux.HandleFunc("GET /api/v1/apps/recent", s.handleRecentApps)
	apiMux.HandleFunc("GET /api/v1/apps/{id}", s.handleGetApp)
	apiMux.HandleFunc("POST /api/v1/apps/launch", s.handleLaunchApp)
	apiMux.HandleFunc("GET /api/v1/hook/status", s.handleHookStatus)
	apiMux.HandleFunc("GET /api/v1/hook/processes", s.handleHookProcesses)
	apiMux.HandleFunc("POST /api/v1/hook/inject", s.handleHookInject)
	apiMux.HandleFunc("GET /api/v1/hook/log", s.handleHookLog)
	apiMux.HandleFunc("POST /api/v1/system/pick-file", s.handlePickFile)
	apiMux.HandleFunc("GET /api/v1/system/proxy-config", s.handleSystemProxyStatus)
	apiMux.HandleFunc("POST /api/v1/system/proxy-config/apply", s.handleSystemProxyApply)
	apiMux.HandleFunc("POST /api/v1/system/proxy-config/restore", s.handleSystemProxyRestore)
	apiMux.HandleFunc("GET /api/v1/cert/status", s.handleCertStatus)
	apiMux.HandleFunc("GET /api/v1/cert/ca", s.handleCertDownload)
	apiMux.HandleFunc("POST /api/v1/cert/install", s.handleCertInstall)
	apiMux.HandleFunc("POST /api/v1/cert/regenerate", s.handleCertRegenerate)
	apiMux.HandleFunc("GET /api/v1/export/har", s.handleExportHAR)

	root := http.NewServeMux()
	root.HandleFunc("GET /healthz", s.handleHealth)
	root.Handle("/api/", s.apiMiddleware(apiMux))
	root.HandleFunc("/", s.handleSPA)

	return s.commonMiddleware(root)
}

func (s *Server) apiMiddleware(next http.Handler) http.Handler {
	h := next
	h = s.csrfGuard(h)
	h = s.originGuard(h)
	h = s.requireAuth(h)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.requestCount.Add(1)
		h.ServeHTTP(w, r)
	})
}

func (s *Server) commonMiddleware(next http.Handler) http.Handler {
	h := next
	h = s.accessLog(h)
	h = s.securityHeaders(h)
	h = s.withRequestID(h)
	h = s.recoverer(h)
	return h
}

func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.opts.Dev {
			ctx := context.WithValue(r.Context(), ctxKeyAuthMethod, authDev)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		if header := r.Header.Get("Authorization"); strings.HasPrefix(header, "Bearer ") {
			token := strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
			if constantEqual(token, s.opts.Token) {
				ctx := context.WithValue(r.Context(), ctxKeyAuthMethod, authBearer)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
		}
		if cookie, err := r.Cookie(sessionCookieName); err == nil && constantEqual(cookie.Value, s.opts.Token) {
			ctx := context.WithValue(r.Context(), ctxKeyAuthMethod, authCookie)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		w.Header().Set("WWW-Authenticate", `Bearer realm="scanning"`)
		writeError(w, r, http.StatusUnauthorized, "UNAUTHORIZED", "缺少或错误的访问令牌", nil)
	})
}

func (s *Server) originGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}
		origin := r.Header.Get("Origin")
		if origin == "" {
			next.ServeHTTP(w, r)
			return
		}
		if method, _ := r.Context().Value(ctxKeyAuthMethod).(authMethod); method == authBearer {
			next.ServeHTTP(w, r)
			return
		}
		u, err := url.Parse(origin)
		if err != nil || u.Host == "" {
			writeError(w, r, http.StatusForbidden, "FORBIDDEN_ORIGIN", "Origin 无效", nil)
			return
		}
		if strings.EqualFold(u.Host, r.Host) {
			next.ServeHTTP(w, r)
			return
		}
		if s.opts.Dev && isDevOrigin(u.Host) {
			next.ServeHTTP(w, r)
			return
		}
		writeError(w, r, http.StatusForbidden, "FORBIDDEN_ORIGIN", "不允许的请求来源", map[string]any{"origin": origin})
	})
}

func (s *Server) csrfGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.opts.Dev {
			next.ServeHTTP(w, r)
			return
		}
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}
		if method, _ := r.Context().Value(ctxKeyAuthMethod).(authMethod); method == authBearer {
			next.ServeHTTP(w, r)
			return
		}
		if r.Header.Get("X-Scanning-Request") != "1" {
			writeError(w, r, http.StatusForbidden, "FORBIDDEN_ORIGIN", "缺少 X-Scanning-Request 请求头", nil)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) withRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-Id")
		if id == "" {
			id = ulid.Make().String()
		}
		w.Header().Set("X-Request-Id", id)
		ctx := context.WithValue(r.Context(), ctxKeyRequestID, id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r)
		if sw.status == 0 {
			sw.status = http.StatusOK
		}
		duration := time.Since(start)
		attrs := []any{
			"method", r.Method,
			"path", r.URL.Path,
			"status", sw.status,
			"duration_ms", duration.Milliseconds(),
		}
		if sw.status >= 500 {
			slog.Warn("请求处理失败", attrs...)
		} else {
			slog.Debug("请求完成", attrs...)
		}
	})
}

func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				slog.Error("panic", "error", rec, "path", r.URL.Path)
				writeError(w, r, http.StatusInternalServerError, "INTERNAL", "内部错误", nil)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) calcQPS() float64 {
	s.statsMu.Lock()
	defer s.statsMu.Unlock()

	now := time.Now()
	count := s.requestCount.Load()
	elapsed := now.Sub(s.lastStatsAt).Seconds()
	if elapsed >= 0.2 {
		s.qps = float64(count-s.lastCount) / elapsed
		s.lastCount = count
		s.lastStatsAt = now
	}
	return s.qps
}

func (s *Server) uptimeSeconds() int64 {
	return int64(time.Since(s.startedAt).Seconds())
}

func requestID(r *http.Request) string {
	if id, ok := r.Context().Value(ctxKeyRequestID).(string); ok {
		return id
	}
	return ""
}

func constantEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func isDevOrigin(host string) bool {
	switch host {
	case "127.0.0.1:5173", "localhost:5173", "127.0.0.1:5174", "localhost:5174":
		return true
	default:
		return false
	}
}

type statusWriter struct {
	http.ResponseWriter
	status  int
	written int
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status != 0 {
		return
	}
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.written += n
	return n, err
}

func (w *statusWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func (w *statusWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (w *statusWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("response writer 不支持 hijack")
	}
	return hijacker.Hijack()
}

type envelope struct {
	Data  any       `json:"data,omitempty"`
	Meta  any       `json:"meta,omitempty"`
	Error *apiError `json:"error,omitempty"`
}

type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details any    `json:"details,omitempty"`
}

func writeData(w http.ResponseWriter, r *http.Request, data any, meta map[string]any) {
	if meta == nil {
		meta = map[string]any{}
	}
	meta["requestId"] = requestID(r)
	writeJSON(w, http.StatusOK, envelope{Data: data, Meta: meta})
}

func writeError(w http.ResponseWriter, r *http.Request, status int, code, message string, details any) {
	writeJSON(w, status, envelope{
		Error: &apiError{Code: code, Message: message, Details: details},
		Meta:  map[string]any{"requestId": requestID(r)},
	})
}

func writeJSON(w http.ResponseWriter, status int, payload envelope) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func isLoopbackRemote(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func platformString() string {
	return runtime.GOOS + "/" + runtime.GOARCH
}

func versionString() string {
	return version.String()
}
