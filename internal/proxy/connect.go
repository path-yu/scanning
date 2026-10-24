package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/textproto"
	"strings"
	"sync"
	"time"

	"scanning/internal/flow"
)

func (e *Engine) handleConnect(w http.ResponseWriter, r *http.Request) {
	host, port := splitHostPortDefault(strings.TrimSpace(r.Host), "443")
	if host == "" {
		http.Error(w, "CONNECT 缺少目标主机", http.StatusBadRequest)
		return
	}
	target := net.JoinHostPort(host, port)
	hookOrigin := strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Scanning-Hook")), "1")

	if !e.cfg.MITM || matchPassthrough(e.cfg.Passthrough, host) {
		e.tunnel(w, target)
		return
	}
	// 注入 Hook 的 CONNECT 目标通常是 IP:80，无法从 CONNECT 行拿到域名；
	// 这里把 80 端口的隧道升级为明文 HTTP 解析，域名由请求的 Host 头还原。
	if hookOrigin && port == "80" {
		e.serveHookHTTP(w)
		return
	}
	// Hook 接管的其他端口（如游戏/长连接端口）通常不是 HTTP；直接建立原始
	// TCP 隧道，避免 TLS MITM 或 HTTP 解析破坏应用协议。这类连接无法解析
	// 内容，但仍记录一条 Flow，便于在界面看到目标、进程与双向字节数。
	if hookOrigin && port != "443" {
		e.tunnelRaw(w, r, host, port, target)
		return
	}
	if e.certs == nil {
		http.Error(w, "证书中心未就绪", http.StatusServiceUnavailable)
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "当前 ResponseWriter 不支持连接接管", http.StatusInternalServerError)
		return
	}
	raw, rw, err := hijacker.Hijack()
	if err != nil {
		return
	}

	owned := true
	e.conns.Add(raw)
	defer func() {
		if owned {
			e.conns.Remove(raw)
			_ = raw.Close()
		}
	}()

	if _, err := rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if err := rw.Flush(); err != nil {
		return
	}

	conn := &bufferedConn{Conn: raw, r: rw.Reader}
	_ = raw.SetReadDeadline(time.Now().Add(5 * time.Second))
	head, err := conn.r.Peek(3)
	_ = raw.SetReadDeadline(time.Time{})
	if err != nil {
		return
	}
	if len(head) < 3 || head[0] != 0x16 || head[1] != 0x03 {
		// 少数客户端会用 CONNECT 建立明文隧道。
		e.tunnelConn(conn, target)
		return
	}

	tlsConn := tls.Server(conn, &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			name := hello.ServerName
			if name == "" {
				name = host
			}
			return e.certs.CertificateFor(name)
		},
	})

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		slog.Debug("客户端 TLS 握手失败", "host", host, "error", err)
		e.recordFailedConnect(e.clientMeta(r.RemoteAddr), host, port, "tls", err)
		return
	}

	if !e.mitmListener.Push(tlsConn) {
		return
	}
	e.conns.Remove(raw)
	owned = false
}

func (e *Engine) serveHookHTTP(w http.ResponseWriter) {
	e.active.Add(1)
	defer e.active.Add(-1)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "当前 ResponseWriter 不支持连接接管", http.StatusInternalServerError)
		return
	}
	raw, rw, err := hijacker.Hijack()
	if err != nil {
		return
	}
	e.conns.Add(raw)
	defer func() {
		e.conns.Remove(raw)
		_ = raw.Close()
	}()

	if _, err := rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if err := rw.Flush(); err != nil {
		return
	}
	conn := &bufferedConn{Conn: raw, r: rw.Reader}
	e.ServeTransparent(conn, "", 80, "http")
}

func (e *Engine) tunnel(w http.ResponseWriter, target string) {
	e.active.Add(1)
	defer e.active.Add(-1)
	upstream, err := e.dialTarget(target)
	if err != nil {
		http.Error(w, "无法连接上游: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer upstream.Close()

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "当前 ResponseWriter 不支持连接接管", http.StatusInternalServerError)
		return
	}
	raw, rw, err := hijacker.Hijack()
	if err != nil {
		return
	}
	e.conns.Add(raw)
	defer func() {
		e.conns.Remove(raw)
		_ = raw.Close()
	}()

	if _, err := rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if err := rw.Flush(); err != nil {
		return
	}

	copyBidirectional(raw, upstream)
}

func (e *Engine) tunnelConn(client net.Conn, target string) {
	e.active.Add(1)
	defer e.active.Add(-1)
	upstream, err := e.dialTarget(target)
	if err != nil {
		_ = client.Close()
		return
	}
	defer upstream.Close()
	copyBidirectional(client, upstream)
}

// tunnelRaw 为注入 Hook 接管的非 HTTP 端口建立原始 TCP 隧道。这类连接
// （如 RDP、游戏私有协议）无法解析内容，但仍记录 Flow，便于在界面看到
// 连接目标、所属进程与双向字节数。
func (e *Engine) tunnelRaw(w http.ResponseWriter, r *http.Request, host, port, target string) {
	e.active.Add(1)
	defer e.active.Add(-1)

	started := time.Now()
	clientIP, clientPort := splitRemote(r.RemoteAddr)
	portNum := parsePort(port, 0)
	f := &flow.Flow{
		Mode:      flow.ModeProxy,
		State:     flow.StateActive,
		Scheme:    "tcp",
		Host:      host,
		Port:      portNum,
		Method:    "CONNECT",
		Client:    e.clientFlowInfo(clientIP, clientPort),
		Server:    flow.ServerInfo{Name: host, Port: portNum},
		Tags:      []string{"raw-tunnel"},
		StartedAt: started,
	}
	f = e.store.Add(f)
	e.hub.Broadcast("flow.created", f.Summary())

	fail := func(err error) {
		completed := time.Now()
		f.State = flow.StateFailed
		f.CompletedAt = &completed
		f.DurationMs = completed.Sub(started).Milliseconds()
		f.Error = &flow.FlowError{Stage: "connect", Code: "raw_tunnel_failed", Message: err.Error()}
		e.syncFlow(f, "flow.updated")
	}

	upstream, err := e.dialTarget(target)
	if err != nil {
		fail(err)
		http.Error(w, "无法连接上游: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer upstream.Close()

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		fail(fmt.Errorf("当前 ResponseWriter 不支持连接接管"))
		http.Error(w, "当前 ResponseWriter 不支持连接接管", http.StatusInternalServerError)
		return
	}
	raw, rw, err := hijacker.Hijack()
	if err != nil {
		fail(err)
		return
	}
	e.conns.Add(raw)
	defer func() {
		e.conns.Remove(raw)
		_ = raw.Close()
	}()

	if _, err := rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		fail(err)
		return
	}
	if err := rw.Flush(); err != nil {
		fail(err)
		return
	}

	requestBytes, responseBytes := copyBidirectional(raw, upstream)
	completed := time.Now()
	f.State = flow.StateCompleted
	f.CompletedAt = &completed
	f.DurationMs = completed.Sub(started).Milliseconds()
	f.ReqSize = requestBytes
	f.RespSize = responseBytes
	e.syncFlow(f, "flow.updated")
}

// dialTarget 直接连接目标；配置了上游代理时通过 HTTP/HTTPS 代理建立 CONNECT 隧道。
func (e *Engine) dialTarget(target string) (net.Conn, error) {
	if e.upstreamURL == nil {
		return net.DialTimeout("tcp", target, 10*time.Second)
	}
	return e.dialViaUpstream(target)
}

func (e *Engine) dialViaUpstream(target string) (net.Conn, error) {
	u := e.upstreamURL
	proxyAddr := u.Host
	if u.Port() == "" {
		port := "80"
		if u.Scheme == "https" {
			port = "443"
		}
		proxyAddr = net.JoinHostPort(u.Hostname(), port)
	}
	conn, err := net.DialTimeout("tcp", proxyAddr, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("连接上游代理 %s: %w", proxyAddr, err)
	}
	closeWith := func(cause error) (net.Conn, error) {
		_ = conn.Close()
		return nil, cause
	}

	if u.Scheme == "https" {
		tlsConn := tls.Client(conn, &tls.Config{
			ServerName: u.Hostname(),
			MinVersion: tls.VersionTLS12,
		})
		if err := tlsConn.Handshake(); err != nil {
			return closeWith(fmt.Errorf("上游代理 TLS 握手失败: %w", err))
		}
		conn = tlsConn
	}

	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	var request strings.Builder
	fmt.Fprintf(&request, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Connection: Keep-Alive\r\n", target, target)
	if u.User != nil {
		password, _ := u.User.Password()
		token := base64.StdEncoding.EncodeToString([]byte(u.User.Username() + ":" + password))
		fmt.Fprintf(&request, "Proxy-Authorization: Basic %s\r\n", token)
	}
	request.WriteString("\r\n")
	if _, err := io.WriteString(conn, request.String()); err != nil {
		return closeWith(fmt.Errorf("向上游代理发送 CONNECT 失败: %w", err))
	}

	reader := bufio.NewReader(conn)
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		return closeWith(fmt.Errorf("读取上游代理响应失败: %w", err))
	}
	fields := strings.SplitN(strings.TrimSpace(statusLine), " ", 3)
	if len(fields) < 2 || fields[1] != "200" {
		return closeWith(fmt.Errorf("上游代理拒绝 CONNECT: %s", strings.TrimSpace(statusLine)))
	}
	if _, err := textproto.NewReader(reader).ReadMIMEHeader(); err != nil {
		return closeWith(fmt.Errorf("读取上游代理响应头失败: %w", err))
	}
	_ = conn.SetDeadline(time.Time{})
	return &bufferedConn{Conn: conn, r: reader}, nil
}

func copyBidirectional(a, b net.Conn) (int64, int64) {
	var once sync.Once
	closeBoth := func() {
		once.Do(func() {
			_ = a.Close()
			_ = b.Close()
		})
	}

	// request 为客户端发往上游的字节，response 为上游返回客户端的字节。
	var request, response int64
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		response, _ = io.Copy(a, b)
		closeBoth()
	}()
	go func() {
		defer wg.Done()
		request, _ = io.Copy(b, a)
		closeBoth()
	}()
	wg.Wait()
	return request, response
}
