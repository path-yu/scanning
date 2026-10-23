package api

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	selfTestStepTimeout = 6 * time.Second
	selfTestDefaultHost = "example.com"
)

type selfTestStep struct {
	Name   string `json:"name"`
	Label  string `json:"label"`
	Status string `json:"status"` // pass | fail | skip
	Ms     int64  `json:"ms"`
	Detail string `json:"detail"`
}

type selfTestResult struct {
	OK            bool           `json:"ok"`
	Target        string         `json:"target"`
	ProxyAddr     string         `json:"proxyAddr"`
	ProxyRunning  bool           `json:"proxyRunning"`
	MITM          bool           `json:"mitm"`
	CertInstalled bool           `json:"certInstalled"`
	Steps         []selfTestStep `json:"steps"`
	TotalMs       int64          `json:"totalMs"`
	FinishedAt    time.Time      `json:"finishedAt"`
}

// handleSelfTest 用一个真实的 HTTPS 请求串起 DNS、代理端口、TLS 解密与 HTTP 往返，
// 供首次引导和故障排查判断“代理 + 根证书 + MITM”是否真正可用。
func (s *Server) handleSelfTest(w http.ResponseWriter, r *http.Request) {
	if s.proxy == nil {
		writeError(w, r, http.StatusServiceUnavailable, "PROXY_UNAVAILABLE", "代理引擎未初始化", nil)
		return
	}
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
	host, port, display, err := parseSelfTestTarget(req.Target)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "BAD_REQUEST", err.Error(), nil)
		return
	}

	status := s.proxy.Status()
	certStatus := s.certs.Status()
	started := time.Now()
	result := selfTestResult{
		Target:        display,
		ProxyAddr:     status.Addr,
		ProxyRunning:  status.Running,
		MITM:          status.MITM,
		CertInstalled: certStatus.Installed,
		Steps:         make([]selfTestStep, 0, 5),
	}

	pass := func(name, label string, at time.Time, detail string) {
		result.Steps = append(result.Steps, selfTestStep{Name: name, Label: label, Status: "pass", Ms: time.Since(at).Milliseconds(), Detail: detail})
	}
	fail := func(name, label string, at time.Time, detail string) {
		result.Steps = append(result.Steps, selfTestStep{Name: name, Label: label, Status: "fail", Ms: time.Since(at).Milliseconds(), Detail: detail})
	}
	skip := func(names ...string) {
		for _, name := range names {
			result.Steps = append(result.Steps, selfTestStep{Name: name, Label: selfTestLabel(name), Status: "skip", Detail: "前置步骤失败，已跳过"})
		}
	}
	finish := func(ok bool) {
		result.OK = ok
		result.TotalMs = time.Since(started).Milliseconds()
		result.FinishedAt = time.Now()
		writeData(w, r, result, nil)
	}

	// 1. 代理端口
	at := time.Now()
	if !status.Running {
		detail := "代理未启动，请先启动代理"
		if status.Error != "" {
			detail += "（" + status.Error + "）"
		}
		fail("proxy", selfTestLabel("proxy"), at, detail)
		skip("dns", "tcp", "tls", "http")
		finish(false)
		return
	}
	pass("proxy", selfTestLabel("proxy"), at, fmt.Sprintf("%s 已监听 · MITM %s", status.Addr, map[bool]string{true: "已启用", false: "未启用"}[status.MITM]))

	// 2. DNS 解析（目标是 IP 时跳过）
	at = time.Now()
	hostIsIP := net.ParseIP(host) != nil
	if hostIsIP {
		pass("dns", selfTestLabel("dns"), at, "目标为 IP 地址，跳过 DNS 解析")
	} else {
		ctx, cancel := context.WithTimeout(r.Context(), selfTestStepTimeout)
		ips, lookupErr := net.DefaultResolver.LookupHost(ctx, host)
		cancel()
		if lookupErr != nil {
			fail("dns", selfTestLabel("dns"), at, "解析 "+host+" 失败: "+lookupErr.Error())
			skip("tcp", "tls", "http")
			finish(false)
			return
		}
		shown := ips
		if len(shown) > 3 {
			shown = shown[:3]
		}
		pass("dns", selfTestLabel("dns"), at, fmt.Sprintf("%s → %s", host, strings.Join(shown, ", ")))
	}

	// 3. 连接代理端口
	at = time.Now()
	dialCtx, cancel := context.WithTimeout(r.Context(), selfTestStepTimeout)
	conn, dialErr := (&net.Dialer{}).DialContext(dialCtx, "tcp", status.Addr)
	cancel()
	if dialErr != nil {
		fail("tcp", selfTestLabel("tcp"), at, "连接代理端口失败: "+dialErr.Error())
		skip("tls", "http")
		finish(false)
		return
	}
	defer conn.Close()
	pass("tcp", selfTestLabel("tcp"), at, "已连接 "+status.Addr)

	// 4. 通过代理 CONNECT 并验证 TLS 证书链
	at = time.Now()
	targetAddr := net.JoinHostPort(host, port)
	if err := conn.SetDeadline(time.Now().Add(selfTestStepTimeout)); err != nil {
		fail("tls", selfTestLabel("tls"), at, "设置超时失败: "+err.Error())
		skip("http")
		finish(false)
		return
	}
	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Scanning-SelfTest/1.0\r\nProxy-Connection: Keep-Alive\r\n\r\n", targetAddr, targetAddr)
	if _, err := io.WriteString(conn, connectReq); err != nil {
		fail("tls", selfTestLabel("tls"), at, "发送 CONNECT 失败: "+err.Error())
		skip("http")
		finish(false)
		return
	}
	br := bufio.NewReader(conn)
	connectResp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		fail("tls", selfTestLabel("tls"), at, "读取 CONNECT 响应失败: "+err.Error())
		skip("http")
		finish(false)
		return
	}
	if connectResp.StatusCode != http.StatusOK {
		detail := fmt.Sprintf("代理拒绝 CONNECT（HTTP %d）", connectResp.StatusCode)
		if connectResp.Body != nil {
			body, _ := io.ReadAll(io.LimitReader(connectResp.Body, 4<<10))
			connectResp.Body.Close()
			if text := strings.TrimSpace(string(body)); text != "" {
				detail += ": " + text
			}
		}
		fail("tls", selfTestLabel("tls"), at, detail)
		skip("http")
		finish(false)
		return
	}

	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(s.certs.CAPEM()) {
		fail("tls", selfTestLabel("tls"), at, "无法加载本工具根证书")
		skip("http")
		finish(false)
		return
	}
	tlsConn := tls.Client(&selfTestBufferedConn{Conn: conn, r: br}, &tls.Config{
		ServerName: host,
		RootCAs:    roots,
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
	})
	handshakeCtx, handshakeCancel := context.WithTimeout(r.Context(), selfTestStepTimeout)
	handshakeErr := tlsConn.HandshakeContext(handshakeCtx)
	handshakeCancel()
	if handshakeErr != nil {
		hint := "HTTPS 解密未生效：请确认代理已启用 MITM，并在客户端信任本工具 CA"
		if !status.MITM {
			hint = "代理未启用 MITM，HTTPS 流量不会被解密；请先开启 MITM"
		}
		fail("tls", selfTestLabel("tls"), at, hint+"（"+handshakeErr.Error()+"）")
		skip("http")
		finish(false)
		return
	}
	state := tlsConn.ConnectionState()
	issuer := ""
	if len(state.PeerCertificates) > 0 {
		issuer = state.PeerCertificates[0].Issuer.CommonName
	}
	pass("tls", selfTestLabel("tls"), at, fmt.Sprintf("%s · %s · 签发者 %s", tlsVersionName(state.Version), tls.CipherSuiteName(state.CipherSuite), issuer))

	// 5. 明文 HTTP/1.1 往返（此时已由代理解密并重新加密）
	at = time.Now()
	_ = tlsConn.SetDeadline(time.Now().Add(selfTestStepTimeout))
	httpReq := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Scanning-SelfTest/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n", targetAddr)
	if _, err := io.WriteString(tlsConn, httpReq); err != nil {
		fail("http", selfTestLabel("http"), at, "发送 HTTPS 请求失败: "+err.Error())
		finish(false)
		return
	}
	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), &http.Request{Method: http.MethodGet})
	if err != nil {
		fail("http", selfTestLabel("http"), at, "读取 HTTPS 响应失败: "+err.Error())
		finish(false)
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	detail := fmt.Sprintf("HTTP %d %s", resp.StatusCode, http.StatusText(resp.StatusCode))
	if resp.StatusCode >= 500 {
		fail("http", selfTestLabel("http"), at, detail+" · 上游返回错误")
		finish(false)
		return
	}
	pass("http", selfTestLabel("http"), at, detail)
	finish(true)
}

func selfTestLabel(name string) string {
	switch name {
	case "proxy":
		return "代理端口"
	case "dns":
		return "DNS 解析"
	case "tcp":
		return "TCP 连接"
	case "tls":
		return "TLS 解密"
	case "http":
		return "HTTPS 请求"
	default:
		return name
	}
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	default:
		return fmt.Sprintf("TLS 0x%04x", version)
	}
}

// parseSelfTestTarget 接受 host、host:port 或完整 URL，默认 443 端口。
func parseSelfTestTarget(raw string) (host, port, display string, err error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		raw = selfTestDefaultHost
	}

	port = "443"
	switch {
	case strings.Contains(raw, "://"):
		u, parseErr := url.Parse(raw)
		if parseErr != nil || u.Hostname() == "" {
			return "", "", "", errors.New("自检目标 URL 无效")
		}
		host = u.Hostname()
		if p := u.Port(); p != "" {
			port = p
		}
	case strings.HasPrefix(raw, "["):
		// [IPv6]:port
		h, p, splitErr := net.SplitHostPort(raw)
		if splitErr != nil {
			return "", "", "", errors.New("自检目标地址无效: " + splitErr.Error())
		}
		host, port = h, p
	default:
		if h, p, splitErr := net.SplitHostPort(raw); splitErr == nil {
			host, port = h, p
		} else {
			host = raw
		}
	}

	host = strings.TrimSuffix(strings.TrimSpace(host), ".")
	if host == "" || strings.ContainsAny(host, " \t\r\n/?#") {
		return "", "", "", errors.New("自检目标主机无效")
	}
	n, convErr := strconv.Atoi(port)
	if convErr != nil || n <= 0 || n > 65535 {
		return "", "", "", errors.New("自检目标端口无效")
	}
	targetAddr := net.JoinHostPort(host, port)
	if port == "443" {
		display = "https://" + host + "/"
	} else {
		display = "https://" + targetAddr + "/"
	}
	return host, port, display, nil
}

type selfTestBufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *selfTestBufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }
