package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"scanning/internal/blob"
	"scanning/internal/config"
	"scanning/internal/event"
	"scanning/internal/flow"
	"scanning/internal/mitm"
	"scanning/internal/procinfo"
	"scanning/internal/rules"
	"scanning/internal/store"
)

type Config struct {
	Addr                       string
	MITM                       bool
	Passthrough                []string
	UpstreamProxy              string
	UpstreamInsecureSkipVerify bool
	MaxBodyBytes               int64
	BreakpointTimeout          time.Duration
}

func FromConfig(c config.ProxyConfig) Config {
	maxBody := c.MaxBodyBytes
	if maxBody <= 0 {
		maxBody = 10 << 20
	}
	timeout := time.Duration(c.BreakpointTimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	return Config{
		Addr:                       c.Addr,
		MITM:                       c.MITM,
		Passthrough:                append([]string(nil), c.Passthrough...),
		UpstreamProxy:              c.UpstreamProxy,
		UpstreamInsecureSkipVerify: c.UpstreamInsecureSkipVerify,
		MaxBodyBytes:               maxBody,
		BreakpointTimeout:          timeout,
	}
}

type Status struct {
	Running       bool     `json:"running"`
	Addr          string   `json:"addr"`
	MITM          bool     `json:"mitm"`
	UpstreamProxy string   `json:"upstreamProxy,omitempty"`
	Connections   int      `json:"connections"`
	UptimeSec     int64    `json:"uptimeSec"`
	Error         string   `json:"error,omitempty"`
	Passthrough   []string `json:"passthrough,omitempty"`
}

type Deps struct {
	Certs     *mitm.Center
	Store     *store.Ring
	Hub       *event.Hub
	Blobs     *blob.Store
	Rules     *rules.Store
	Processes *procinfo.Resolver
	SessionID string
}

type Engine struct {
	cfg         Config
	certs       *mitm.Center
	store       *store.Ring
	hub         *event.Hub
	blobs       *blob.Store
	rules       *rules.Store
	processes   *procinfo.Resolver
	gate        *Gate
	sessionID   string
	transport   *http.Transport
	upstreamURL *url.URL
	localPort   atomic.Int32

	flowObserver func(*flow.Flow)
	observerMu   sync.RWMutex

	mu           sync.Mutex
	running      bool
	addr         string
	startedAt    time.Time
	lastErr      string
	listener     net.Listener
	mitmListener *connListener
	httpServer   *http.Server
	mitmServer   *http.Server

	active atomic.Int64
	conns  connSet
}

func New(cfg Config, deps Deps) *Engine {
	if cfg.Addr == "" {
		cfg.Addr = "127.0.0.1:8899"
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = 10 << 20
	}
	if cfg.BreakpointTimeout <= 0 {
		cfg.BreakpointTimeout = 60 * time.Second
	}
	blobs := deps.Blobs
	if blobs == nil {
		blobs, _ = blob.New("")
	}
	ruleStore := deps.Rules
	if ruleStore == nil {
		ruleStore, _ = rules.NewStore("")
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	var upstreamURL *url.URL
	var upstreamProxy func(*http.Request) (*url.URL, error)
	if cfg.UpstreamProxy != "" {
		parsed, parseErr := config.ParseUpstreamProxy(cfg.UpstreamProxy)
		if parseErr != nil {
			slog.Warn("上游代理配置无效，将直接连接上游", "value", cfg.UpstreamProxy, "error", parseErr)
		} else if parsed != nil {
			upstreamURL = parsed
			upstreamProxy = http.ProxyURL(parsed)
			slog.Info("已启用上游代理", "upstream", parsed.Redacted())
		}
	}
	transport := &http.Transport{
		Proxy:                 upstreamProxy,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          256,
		MaxIdleConnsPerHost:   16,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: cfg.UpstreamInsecureSkipVerify,
		},
	}
	return &Engine{
		cfg:         cfg,
		certs:       deps.Certs,
		store:       deps.Store,
		hub:         deps.Hub,
		blobs:       blobs,
		rules:       ruleStore,
		processes:   deps.Processes,
		gate:        NewGate(),
		sessionID:   deps.SessionID,
		transport:   transport,
		upstreamURL: upstreamURL,
		conns:       connSet{m: make(map[net.Conn]struct{})},
	}
}

// Blobs 返回正文存储，供 API 读取完整正文与导出 HAR。
func (e *Engine) Blobs() *blob.Store { return e.blobs }

// Rules 返回规则存储。
func (e *Engine) Rules() *rules.Store { return e.rules }

// SetFlowObserver 注册完成 Flow 的观察者（例如写网卡镜像报文）。
func (e *Engine) SetFlowObserver(fn func(*flow.Flow)) {
	e.observerMu.Lock()
	e.flowObserver = fn
	e.observerMu.Unlock()
}

func (e *Engine) notifyFlowObserver(f *flow.Flow) {
	if f == nil {
		return
	}
	e.observerMu.RLock()
	fn := e.flowObserver
	e.observerMu.RUnlock()
	if fn != nil {
		fn(f.Clone())
	}
}

// Resume 放行一个处于断点等待中的 Flow。
func (e *Engine) Resume(id string, cmd ResumeCommand) bool {
	return e.gate.Resume(id, cmd)
}

// Paused 返回当前处于断点等待中的 Flow ID。
func (e *Engine) Paused() []string { return e.gate.Pending() }

func (e *Engine) Start() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.running {
		return nil
	}

	ln, err := net.Listen("tcp", e.cfg.Addr)
	if err != nil {
		e.lastErr = err.Error()
		return fmt.Errorf("监听代理地址 %s: %w", e.cfg.Addr, err)
	}

	ml := newConnListener(ln.Addr())
	httpSrv := &http.Server{
		Handler:           e,
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       90 * time.Second,
	}
	mitmSrv := &http.Server{
		Handler:           http.HandlerFunc(e.handleMITM),
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       90 * time.Second,
	}

	e.listener = ln
	e.mitmListener = ml
	e.httpServer = httpSrv
	e.mitmServer = mitmSrv
	e.addr = ln.Addr().String()
	if tcpAddr, ok := ln.Addr().(*net.TCPAddr); ok {
		e.localPort.Store(int32(tcpAddr.Port))
	}
	e.startedAt = time.Now()
	e.lastErr = ""
	e.running = true

	go func() {
		if err := httpSrv.Serve(ln); err != nil && !isClosedError(err) {
			slog.Error("代理监听异常退出", "error", err)
			e.setFailure(err)
		}
	}()
	go func() {
		if err := mitmSrv.Serve(ml); err != nil && !isClosedError(err) {
			slog.Warn("MITM 连接服务退出", "error", err)
		}
	}()

	slog.Info("HTTP/HTTPS 代理已启动", "addr", e.addr, "mitm", e.cfg.MITM)
	return nil
}

func (e *Engine) Stop(ctx context.Context) error {
	e.mu.Lock()
	if !e.running {
		e.mu.Unlock()
		return nil
	}
	e.running = false
	httpSrv := e.httpServer
	mitmSrv := e.mitmServer
	ml := e.mitmListener
	ln := e.listener
	e.mu.Unlock()

	e.gate.ReleaseAll(ResumeCommand{Action: ResumeAbort})

	if httpSrv != nil {
		_ = httpSrv.Shutdown(ctx)
	}
	if mitmSrv != nil {
		_ = mitmSrv.Shutdown(ctx)
	}
	if ml != nil {
		_ = ml.Close()
	}
	if ln != nil {
		_ = ln.Close()
	}
	e.conns.CloseAll()
	slog.Info("HTTP/HTTPS 代理已停止")
	return nil
}

func (e *Engine) Status() Status {
	e.mu.Lock()
	running := e.running
	addr := e.addr
	if addr == "" {
		addr = e.cfg.Addr
	}
	startedAt := e.startedAt
	lastErr := e.lastErr
	e.mu.Unlock()

	var uptime int64
	if running {
		uptime = int64(time.Since(startedAt).Seconds())
	}
	upstream := ""
	if e.upstreamURL != nil {
		upstream = e.upstreamURL.Redacted()
	}
	return Status{
		Running:       running,
		Addr:          addr,
		MITM:          e.cfg.MITM,
		UpstreamProxy: upstream,
		Connections:   int(e.active.Load()),
		UptimeSec:     uptime,
		Error:         lastErr,
		Passthrough:   append([]string(nil), e.cfg.Passthrough...),
	}
}

func (e *Engine) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		e.handleConnect(w, r)
		return
	}
	if r.Header.Get("Upgrade") != "" {
		http.Error(w, "WebSocket upgrade is not supported in M1", http.StatusNotImplemented)
		return
	}
	if !r.URL.IsAbs() {
		http.Error(w, "这是代理端口，请把当前地址配置为 HTTP 代理后访问", http.StatusBadRequest)
		return
	}
	scheme := strings.ToLower(r.URL.Scheme)
	if scheme == "" {
		scheme = "http"
	}
	host := r.URL.Hostname()
	port := r.URL.Port()
	if port == "" {
		port = defaultPort(scheme)
	}
	e.active.Add(1)
	defer e.active.Add(-1)
	e.forward(w, r, scheme, host, parsePort(port, 80))
}

func (e *Engine) handleMITM(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Upgrade") != "" {
		http.Error(w, "WebSocket upgrade is not supported in M1", http.StatusNotImplemented)
		return
	}
	host, port := splitHostPortDefault(r.Host, "443")
	if host == "" {
		http.Error(w, "missing target host", http.StatusBadRequest)
		return
	}
	e.active.Add(1)
	defer e.active.Add(-1)
	e.forward(w, r, "https", host, parsePort(port, 443))
}

func (e *Engine) setFailure(err error) {
	e.mu.Lock()
	e.lastErr = err.Error()
	e.running = false
	ln := e.listener
	ml := e.mitmListener
	e.mu.Unlock()

	if ln != nil {
		_ = ln.Close()
	}
	if ml != nil {
		_ = ml.Close()
	}
	e.conns.CloseAll()
}

func (e *Engine) broadcastStatus() {
	e.hub.Broadcast("proxy.status", e.Status())
}

func splitHostPortDefault(value, defaultPort string) (string, string) {
	host := value
	port := defaultPort
	if strings.Contains(value, ":") {
		if h, p, err := net.SplitHostPort(value); err == nil {
			host, port = h, p
		}
	}
	return strings.TrimSuffix(strings.ToLower(host), "."), port
}

func defaultPort(scheme string) string {
	switch strings.ToLower(scheme) {
	case "https", "wss":
		return "443"
	default:
		return "80"
	}
}

func isClosedError(err error) bool {
	return errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed)
}

// recordFailedConnect 在 TLS 握手失败等情况下记录一条失败 Flow，便于 UI 解释原因。
func (e *Engine) recordFailedConnect(client ClientMeta, host, port string, stage string, err error) {
	now := time.Now()
	f := &flow.Flow{
		Mode:        flow.ModeProxy,
		State:       flow.StateFailed,
		Scheme:      "https",
		Host:        host,
		Port:        parsePort(port, 443),
		Method:      "CONNECT",
		Path:        "",
		Client:      client.Info,
		Server:      flow.ServerInfo{Port: parsePort(port, 443), Name: host},
		Error:       &flow.FlowError{Stage: stage, Code: "proxy_connect_failed", Message: err.Error()},
		Tags:        []string{},
		StartedAt:   now,
		CompletedAt: &now,
	}
	added := e.store.Add(f)
	e.hub.Broadcast("flow.created", added.Summary())
}

type ClientMeta struct {
	Info flow.ClientInfo
}

func (e *Engine) clientMeta(remoteAddr string) ClientMeta {
	host, port, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return ClientMeta{Info: flow.ClientInfo{IP: remoteAddr, Origin: "proxy"}}
	}
	return ClientMeta{Info: e.clientFlowInfo(host, parsePort(port, 0))}
}

// clientFlowInfo 组装客户端信息，并尽力解析所属进程。
func (e *Engine) clientFlowInfo(ip string, port int) flow.ClientInfo {
	info := flow.ClientInfo{IP: ip, Port: port, Origin: "proxy"}
	if e.processes == nil {
		return info
	}
	proc, ok := e.processes.Resolve(ip, port, int(e.localPort.Load()))
	if !ok {
		return info
	}
	info.App = proc.Name
	info.PID = proc.PID
	info.AppPath = proc.Path
	return info
}

func parsePort(value string, fallback int) int {
	n := 0
	for _, r := range value {
		if r < '0' || r > '9' {
			return fallback
		}
		n = n*10 + int(r-'0')
	}
	if n <= 0 || n > 65535 {
		return fallback
	}
	return n
}
