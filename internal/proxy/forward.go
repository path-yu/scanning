package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"scanning/internal/blob"
	"scanning/internal/eapi"
	"scanning/internal/flow"
	"scanning/internal/rules"
)

type syntheticResponse struct {
	Status  int
	Headers flow.Headers
	Body    []byte
}

func (e *Engine) forward(w http.ResponseWriter, r *http.Request, scheme, host string, port int) {
	started := time.Now()
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" {
		http.Error(w, "缺少上游主机", http.StatusBadRequest)
		return
	}

	maxCapture := int(e.cfg.MaxBodyBytes)
	if maxCapture <= 0 {
		maxCapture = 10 << 20
	}
	if maxCapture > 64<<20 {
		maxCapture = 64 << 20
	}
	// EAPI 响应需要完整密文才能解密，单独的响应上限放宽到 32 MB。
	respMaxCapture := maxCapture
	if eapi.IsEAPI(host, r.URL.Path) && respMaxCapture < 32<<20 {
		respMaxCapture = 32 << 20
	}

	prefix, err := readPrefix(r.Body, maxCapture)
	if err != nil {
		http.Error(w, "读取请求正文失败: "+err.Error(), http.StatusBadRequest)
		return
	}

	reqSize := r.ContentLength
	if reqSize < 0 {
		reqSize = int64(len(prefix))
	}
	reqMime := r.Header.Get("Content-Type")
	reqEncoding := r.Header.Get("Content-Encoding")
	reqCaptured := truncateBytes(prefix, maxCapture)
	reqBody := e.makeBody(reqCaptured, reqSize, reqMime, reqEncoding)
	reqDecrypted := false
	if eapi.IsEAPI(host, r.URL.Path) {
		if decoded, ok := eapi.DecryptRequest(reqCaptured); ok {
			reqBody = e.makeBodyDecrypted(reqCaptured, reqSize, reqMime, reqEncoding, decoded)
			reqDecrypted = true
		}
	}

	clientIP, clientPort := splitRemote(r.RemoteAddr)
	trace := &traceState{started: started}

	f := e.newActiveFlow(r, scheme, host, port, reqSize, reqBody, clientIP, clientPort, started)
	if reqDecrypted {
		f.Tags = appendUnique(f.Tags, "eapi-decrypted")
	}
	f = e.store.Add(f)
	e.hub.Broadcast("flow.created", f.Summary())

	target := &url.URL{
		Scheme:   scheme,
		Host:     hostForURL(host, port, scheme),
		Path:     r.URL.Path,
		RawPath:  r.URL.RawPath,
		RawQuery: r.URL.RawQuery,
	}
	method := r.Method
	reqHeaders := r.Header.Clone()
	removeHopByHop(reqHeaders)
	reqHost := r.Host
	if reqHost == "" {
		reqHost = host
	}
	bodyBytes := prefix
	bodyChanged := false

	matchBody := blob.DecodeLimited(reqCaptured, reqEncoding, 512<<10)
	reqMeta := rules.Meta{
		Method:  method,
		Host:    host,
		Path:    target.RequestURI(),
		Mime:    reqMime,
		Headers: requestHeaders(r),
		Body:    matchBody,
	}

	var mock *syntheticResponse
	requestRules := e.rules.Match(rules.PhaseRequest, reqMeta)
	for _, rule := range requestRules {
		f.MatchedRules = appendUnique(f.MatchedRules, rule.Name)
		for _, action := range rule.Actions {
			switch strings.ToLower(action.Type) {
			case rules.ActionDelay:
				if action.DelayMs > 0 {
					if !sleepContext(r.Context(), time.Duration(action.DelayMs)*time.Millisecond) {
						e.failFlow(f, "client", context.Canceled, 499)
						return
					}
				}
			case rules.ActionBlock:
				mock = syntheticFromAction(action, rule.Name, http.StatusForbidden)
			case rules.ActionMock:
				mock = syntheticFromAction(action, rule.Name, http.StatusOK)
			case rules.ActionMapRemote:
				newScheme, newHost, newPort, err := parseRemote(action.Remote, target.Scheme, host, port)
				if err != nil {
					slog.Warn("规则 map_remote 目标无效", "rule", rule.Name, "remote", action.Remote, "error", err)
				} else {
					scheme, host, port = newScheme, newHost, newPort
					target.Scheme = scheme
					target.Host = hostForURL(host, port, scheme)
				}
			case rules.ActionRewriteRequest:
				if action.Method != "" {
					method = strings.ToUpper(strings.TrimSpace(action.Method))
				}
				if action.Path != "" {
					applyTargetPath(target, action.Path)
				}
				applyActionHeaders(reqHeaders, action)
				if action.Body != nil {
					bodyBytes = []byte(*action.Body)
					bodyChanged = true
					reqSize = int64(len(bodyBytes))
					reqEncoding = ""
					reqHeaders.Del("Content-Encoding")
					reqHeaders.Set("Content-Length", strconv.FormatInt(reqSize, 10))
					reqMime = reqHeaders.Get("Content-Type")
				}
				if hostHeader := reqHeaders.Get("Host"); hostHeader != "" {
					reqHost = hostHeader
					reqHeaders.Del("Host")
				}
			case rules.ActionPause:
				cmd := e.pauseFlow(r.Context(), f, "request")
				switch cmd.Action {
				case ResumeAbort:
					mock = syntheticFromResume(cmd, http.StatusBadGateway, "请求已在断点处中止")
				case ResumeMock:
					mock = syntheticFromResume(cmd, http.StatusOK, "")
				default:
					if cmd.Method != "" {
						method = strings.ToUpper(strings.TrimSpace(cmd.Method))
					}
					if cmd.Path != "" {
						applyTargetPath(target, cmd.Path)
					}
					applyResumeHeaders(reqHeaders, cmd.Headers)
					if cmd.Body != nil {
						bodyBytes = []byte(*cmd.Body)
						bodyChanged = true
						reqSize = int64(len(bodyBytes))
						reqEncoding = ""
						reqHeaders.Del("Content-Encoding")
						reqHeaders.Set("Content-Length", strconv.FormatInt(reqSize, 10))
						reqMime = reqHeaders.Get("Content-Type")
					}
				}
			}
			if mock != nil {
				break
			}
		}
		if mock != nil || rule.Stop {
			break
		}
	}

	f.Method = method
	f.Path = target.RequestURI()
	f.ReqSize = reqSize
	f.Request.Headers = requestHeadersFrom(reqHeaders, reqHost)
	if bodyChanged {
		f.Request.Body = e.makeBody(bodyBytes, reqSize, reqMime, reqEncoding)
	}

	if mock != nil {
		e.writeSynthetic(w, *mock)
		f.StatusCode = mock.Status
		f.Response = &flow.Message{
			HTTPVersion: "HTTP/1.1",
			Headers:     mock.Headers,
			Body:        e.makeBody(mock.Body, int64(len(mock.Body)), mock.Headers.Get("Content-Type"), ""),
		}
		f.Mime = mock.Headers.Get("Content-Type")
		f.RespSize = int64(len(mock.Body))
		e.completeFlow(f, trace, host, port, started)
		return
	}

	var bodyReader io.ReadCloser = http.NoBody
	if bodyChanged {
		bodyReader = io.NopCloser(bytes.NewReader(bodyBytes))
	} else if len(prefix) > 0 || r.ContentLength != 0 {
		bodyReader = io.NopCloser(io.MultiReader(bytes.NewReader(prefix), r.Body))
	}

	req, err := http.NewRequestWithContext(r.Context(), method, target.String(), bodyReader)
	if err != nil {
		e.failFlow(f, "http", err, http.StatusBadGateway)
		http.Error(w, "构造上游请求失败: "+err.Error(), http.StatusBadGateway)
		return
	}
	req.Header = reqHeaders.Clone()
	removeHopByHop(req.Header)
	req.Host = reqHost
	req.ContentLength = r.ContentLength
	if bodyChanged {
		req.ContentLength = int64(len(bodyBytes))
	} else if req.ContentLength == 0 && len(prefix) > 0 {
		req.ContentLength = -1
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace.clientTrace()))

	resp, err := e.transport.RoundTrip(req)
	if err != nil {
		e.failFlow(f, stageOf(err), err, http.StatusBadGateway)
		http.Error(w, "上游请求失败: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	respHeaders := resp.Header.Clone()
	removeHopByHop(respHeaders)
	status := resp.StatusCode
	respMime := respHeaders.Get("Content-Type")
	respEncoding := respHeaders.Get("Content-Encoding")

	// SSE 等长连接响应不做缓冲，避免破坏实时性；此时不支持响应阶段规则。
	if isEventStream(respMime) {
		copyHeader(w.Header(), respHeaders)
		w.WriteHeader(status)
		capture := &captureWriter{w: w, limit: maxCapture}
		_, copyErr := io.Copy(capture, resp.Body)
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		captured := capture.buf.Bytes()
		respSize := capture.total
		if respSize < int64(len(captured)) {
			respSize = int64(len(captured))
		}
		f.StatusCode = status
		f.Mime = respMime
		f.RespSize = respSize
		f.Response = &flow.Message{
			HTTPVersion: resp.Proto,
			Headers:     responseHeaders(respHeaders),
			Body:        e.makeBody(captured, respSize, respMime, respEncoding),
		}
		if copyErr != nil {
			f.Error = &flow.FlowError{Stage: "client", Code: "relay_error", Message: copyErr.Error()}
		}
		e.completeFlow(f, trace, host, port, started)
		return
	}

	capturedAll, readErr := readPrefix(resp.Body, respMaxCapture)
	if readErr != nil && len(capturedAll) == 0 {
		e.failFlow(f, "read", readErr, http.StatusBadGateway)
		http.Error(w, "读取上游响应失败: "+readErr.Error(), http.StatusBadGateway)
		return
	}
	respCaptured := truncateBytes(capturedAll, respMaxCapture)
	hasMore := len(capturedAll) > len(respCaptured)
	respSize := resp.ContentLength
	if respSize < 0 {
		respSize = int64(len(capturedAll))
	}
	if respSize < int64(len(respCaptured)) {
		respSize = int64(len(respCaptured))
	}
	decodedResp := blob.DecodeLimited(respCaptured, respEncoding, 512<<10)

	// 先同步状态，保证响应阶段断点暂停时 UI 能看到上游状态码。
	f.StatusCode = status
	f.Mime = respMime
	f.RespSize = respSize

	respMeta := rules.Meta{
		Method:  method,
		Host:    host,
		Path:    target.RequestURI(),
		Status:  status,
		Mime:    respMime,
		Headers: responseHeaders(respHeaders),
		Body:    decodedResp,
	}
	bodyRewritten := false
	var respMock *syntheticResponse
	responseRules := e.rules.Match(rules.PhaseResponse, respMeta)
	for _, rule := range responseRules {
		f.MatchedRules = appendUnique(f.MatchedRules, rule.Name)
		for _, action := range rule.Actions {
			switch strings.ToLower(action.Type) {
			case rules.ActionDelay:
				if action.DelayMs > 0 {
					if !sleepContext(r.Context(), time.Duration(action.DelayMs)*time.Millisecond) {
						e.failFlow(f, "client", context.Canceled, 499)
						return
					}
				}
			case rules.ActionBlock:
				respMock = syntheticFromAction(action, rule.Name, http.StatusForbidden)
			case rules.ActionMock:
				respMock = syntheticFromAction(action, rule.Name, http.StatusOK)
			case rules.ActionRewriteResponse:
				if action.Status != 0 {
					status = action.Status
				}
				applyActionHeaders(respHeaders, action)
				if action.Body != nil {
					respCaptured = []byte(*action.Body)
					hasMore = false
					bodyRewritten = true
					respEncoding = ""
					respHeaders.Del("Content-Encoding")
					respHeaders.Set("Content-Length", strconv.Itoa(len(respCaptured)))
					respSize = int64(len(respCaptured))
					respMime = respHeaders.Get("Content-Type")
				}
			case rules.ActionPause:
				cmd := e.pauseFlow(r.Context(), f, "response")
				switch cmd.Action {
				case ResumeAbort:
					respMock = syntheticFromResume(cmd, http.StatusBadGateway, "响应已在断点处中止")
				case ResumeMock:
					respMock = syntheticFromResume(cmd, http.StatusOK, "")
				default:
					if cmd.Status != 0 {
						status = cmd.Status
					}
					applyResumeHeaders(respHeaders, cmd.Headers)
					if cmd.Body != nil {
						respCaptured = []byte(*cmd.Body)
						hasMore = false
						bodyRewritten = true
						respEncoding = ""
						respHeaders.Del("Content-Encoding")
						respHeaders.Set("Content-Length", strconv.Itoa(len(respCaptured)))
						respSize = int64(len(respCaptured))
						respMime = respHeaders.Get("Content-Type")
					}
				}
			}
			if respMock != nil {
				break
			}
		}
		if respMock != nil || rule.Stop {
			break
		}
	}

	if respMock != nil {
		e.writeSynthetic(w, *respMock)
		f.StatusCode = respMock.Status
		f.Mime = respMock.Headers.Get("Content-Type")
		f.RespSize = int64(len(respMock.Body))
		f.Response = &flow.Message{
			HTTPVersion: "HTTP/1.1",
			Headers:     respMock.Headers,
			Body:        e.makeBody(respMock.Body, int64(len(respMock.Body)), f.Mime, ""),
		}
		e.completeFlow(f, trace, host, port, started)
		return
	}

	copyHeader(w.Header(), respHeaders)
	if bodyRewritten {
		w.Header().Del("Transfer-Encoding")
	}
	w.WriteHeader(status)
	if len(respCaptured) > 0 {
		_, _ = w.Write(respCaptured)
	}
	if hasMore && !bodyRewritten {
		_, _ = io.Copy(w, resp.Body)
	}
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}

	f.StatusCode = status
	f.Mime = respMime
	f.RespSize = respSize
	respBody := e.makeBody(respCaptured, respSize, respMime, respEncoding)
	respDecrypted := false
	if !hasMore && eapi.IsEAPI(host, r.URL.Path) {
		if decoded, ok := eapi.DecryptResponse(respCaptured); ok {
			respBody = e.makeBodyDecrypted(respCaptured, respSize, respMime, respEncoding, decoded)
			respDecrypted = true
		}
	}
	f.Response = &flow.Message{
		HTTPVersion: resp.Proto,
		Headers:     responseHeaders(respHeaders),
		Body:        respBody,
	}
	if respDecrypted {
		f.Tags = appendUnique(f.Tags, "eapi-decrypted")
	}
	e.completeFlow(f, trace, host, port, started)
}

func (e *Engine) newActiveFlow(
	r *http.Request,
	scheme, host string,
	port int,
	reqSize int64,
	reqBody *flow.Body,
	clientIP string,
	clientPort int,
	started time.Time,
) *flow.Flow {
	return &flow.Flow{
		Mode:      flow.ModeProxy,
		State:     flow.StateActive,
		Scheme:    scheme,
		Host:      host,
		Port:      port,
		Method:    r.Method,
		Path:      requestPath(r),
		ReqSize:   reqSize,
		Client:    e.clientFlowInfo(clientIP, clientPort),
		Server:    flow.ServerInfo{Port: port, Name: host},
		Request:   &flow.Message{HTTPVersion: r.Proto, Headers: requestHeaders(r), Body: reqBody},
		Tags:      []string{},
		StartedAt: started,
	}
}

// pauseFlow 将 Flow 置为暂停并等待放行，返回放行指令。
func (e *Engine) pauseFlow(ctx context.Context, f *flow.Flow, phase string) ResumeCommand {
	cmd := e.gate.Pause(ctx, f.ID, e.cfg.BreakpointTimeout, func() {
		f.State = flow.StatePaused
		f.Breakpoint = true
		stored := e.syncFlow(f, "flow.updated")
		e.hub.Broadcast("flow.paused", map[string]any{"flow": stored.Summary(), "phase": phase})
	})
	f.State = flow.StateActive
	stored := e.syncFlow(f, "flow.updated")
	e.hub.Broadcast("flow.resumed", map[string]any{
		"flow":   stored.Summary(),
		"phase":  phase,
		"action": cmd.Action,
	})
	return cmd
}

// syncFlow 用当前快照替换存储中的 Flow 并广播事件，返回存储中的克隆。
func (e *Engine) syncFlow(f *flow.Flow, event string) *flow.Flow {
	result := f
	if updated, ok := e.store.Replace(f); ok {
		result = updated
	}
	e.hub.Broadcast(event, result.Summary())
	return result
}

func (e *Engine) completeFlow(f *flow.Flow, trace *traceState, host string, port int, started time.Time) {
	completed := time.Now()
	f.State = flow.StateCompleted
	f.CompletedAt = &completed
	f.DurationMs = completed.Sub(started).Milliseconds()
	f.Timing = trace.timing(completed)
	f.TLS = trace.tlsInfo(host, e.cfg.UpstreamInsecureSkipVerify)
	if ip := trace.remoteIP(); ip != "" {
		f.Server.IP = ip
	}
	e.syncFlow(f, "flow.completed")
	e.notifyFlowObserver(f)
}

func (e *Engine) failFlow(f *flow.Flow, stage string, err error, status int) {
	completed := time.Now()
	f.State = flow.StateFailed
	f.StatusCode = status
	f.Mime = "text/plain"
	f.Error = &flow.FlowError{Stage: stage, Code: "upstream_error", Message: err.Error()}
	f.CompletedAt = &completed
	f.DurationMs = completed.Sub(f.StartedAt).Milliseconds()
	e.syncFlow(f, "flow.completed")
}

func stageOf(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, context.Canceled):
		return "client"
	case strings.Contains(strings.ToLower(err.Error()), "tls"):
		return "tls"
	case isNetworkError(err):
		return "tcp"
	default:
		return "http"
	}
}

func (e *Engine) writeSynthetic(w http.ResponseWriter, resp syntheticResponse) {
	headers := resp.Headers
	if headers.Get("Content-Type") == "" && len(resp.Body) > 0 {
		headers = headers.Set("Content-Type", detectTextMime(resp.Body))
	}
	for _, header := range headers {
		w.Header().Add(header.Name, header.Value)
	}
	w.Header().Set("X-Scanning-Mock", "1")
	w.Header().Set("Content-Length", strconv.Itoa(len(resp.Body)))
	w.WriteHeader(resp.Status)
	if len(resp.Body) > 0 {
		_, _ = w.Write(resp.Body)
	}
}

func syntheticFromAction(action rules.Action, ruleName string, defaultStatus int) *syntheticResponse {
	status := action.Status
	if status == 0 {
		status = defaultStatus
	}
	var body []byte
	if action.Body != nil {
		body = []byte(*action.Body)
	} else if defaultStatus == http.StatusForbidden {
		body = []byte(fmt.Sprintf(`{"error":"blocked","rule":%q}`, ruleName))
	}
	headers := make(flow.Headers, len(action.Headers))
	copy(headers, action.Headers)
	if len(body) > 0 && headers.Get("Content-Type") == "" {
		headers = headers.Set("Content-Type", detectTextMime(body))
	}
	return &syntheticResponse{Status: status, Headers: headers, Body: body}
}

func syntheticFromResume(cmd ResumeCommand, defaultStatus int, fallbackBody string) *syntheticResponse {
	status := cmd.Status
	if status == 0 {
		status = defaultStatus
	}
	body := fallbackBody
	if cmd.Body != nil {
		body = *cmd.Body
	}
	headers := make(flow.Headers, len(cmd.Headers))
	copy(headers, cmd.Headers)
	if len(body) > 0 && headers.Get("Content-Type") == "" {
		headers = headers.Set("Content-Type", detectTextMime([]byte(body)))
	}
	return &syntheticResponse{Status: status, Headers: headers, Body: []byte(body)}
}

func detectTextMime(data []byte) string {
	mime := http.DetectContentType(data)
	if strings.HasPrefix(mime, "text/plain") {
		return "text/plain; charset=utf-8"
	}
	return mime
}

func applyActionHeaders(headers http.Header, action rules.Action) {
	for _, header := range action.Headers {
		if strings.TrimSpace(header.Name) == "" {
			continue
		}
		headers.Set(header.Name, header.Value)
	}
	for _, name := range action.RemoveHeaders {
		headers.Del(name)
	}
}

func applyResumeHeaders(headers http.Header, items []flow.Header) {
	for _, header := range items {
		if strings.TrimSpace(header.Name) == "" {
			continue
		}
		headers.Set(header.Name, header.Value)
	}
}

func applyTargetPath(target *url.URL, raw string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		target.Path = raw
		target.RawPath = ""
		target.RawQuery = ""
		return
	}
	target.Path = parsed.Path
	target.RawPath = parsed.RawPath
	target.RawQuery = parsed.RawQuery
}

func parseRemote(remote, fallbackScheme, fallbackHost string, fallbackPort int) (string, string, int, error) {
	remote = strings.TrimSpace(remote)
	if remote == "" {
		return "", "", 0, errors.New("目标为空")
	}
	if strings.Contains(remote, "://") {
		u, err := url.Parse(remote)
		if err != nil {
			return "", "", 0, err
		}
		scheme := strings.ToLower(u.Scheme)
		if scheme != "http" && scheme != "https" {
			return "", "", 0, fmt.Errorf("不支持的协议 %s", scheme)
		}
		host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
		if host == "" {
			return "", "", 0, errors.New("缺少主机")
		}
		port := fallbackPort
		if u.Port() != "" {
			port = parsePort(u.Port(), 0)
		} else {
			port = defaultPortInt(scheme)
		}
		return scheme, host, port, nil
	}
	host, portText, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
		portText = ""
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	port := fallbackPort
	if portText != "" {
		port = parsePort(portText, 0)
		if port == 0 {
			return "", "", 0, fmt.Errorf("端口无效: %s", portText)
		}
	}
	scheme := fallbackScheme
	if host == "" {
		host = fallbackHost
	}
	return scheme, host, port, nil
}

func defaultPortInt(scheme string) int {
	if scheme == "https" {
		return 443
	}
	return 80
}

func appendUnique(items []string, value string) []string {
	if value == "" {
		return items
	}
	for _, item := range items {
		if item == value {
			return items
		}
	}
	return append(items, value)
}

func sleepContext(ctx context.Context, delay time.Duration) bool {
	if delay <= 0 {
		return true
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

func isEventStream(mime string) bool {
	return strings.Contains(strings.ToLower(mime), "text/event-stream")
}

func truncateBytes(data []byte, max int) []byte {
	if max > 0 && len(data) > max {
		return data[:max]
	}
	return data
}

func readPrefix(body io.ReadCloser, max int) ([]byte, error) {
	if body == nil || body == http.NoBody || max <= 0 {
		return nil, nil
	}
	var buf bytes.Buffer
	buf.Grow(min(max, 32*1024))
	_, err := io.CopyN(&buf, body, int64(max)+1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return buf.Bytes(), nil
}

type captureWriter struct {
	w     io.Writer
	buf   bytes.Buffer
	limit int
	total int64
}

func (c *captureWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.total += int64(n)
	if n > 0 && c.buf.Len() < c.limit {
		remaining := c.limit - c.buf.Len()
		if remaining > n {
			remaining = n
		}
		_, _ = c.buf.Write(p[:remaining])
	}
	return n, err
}

func (e *Engine) makeBody(data []byte, size int64, mime, encoding string) *flow.Body {
	if len(data) == 0 && size == 0 {
		return nil
	}
	if size < int64(len(data)) {
		size = int64(len(data))
	}
	text, preview := decodePreview(data, encoding, mime)
	ref, err := e.blobs.Put(data)
	if err != nil {
		slog.Warn("保存正文失败，仅保留预览", "error", err, "size", len(data))
	}
	return &flow.Body{
		Ref:          ref,
		Size:         size,
		CapturedSize: int64(len(data)),
		Truncated:    size > int64(len(data)),
		Mime:         mime,
		Encoding:     encoding,
		Text:         text,
		Preview:      preview,
	}
}

// makeBodyDecrypted 保存原始正文，同时用解密后的 JSON 生成预览。
// Text 仍表示原始正文是否为文本；前端根据 Decrypted 判断是否展示解密内容。
func (e *Engine) makeBodyDecrypted(data []byte, size int64, mime, encoding string, decoded []byte) *flow.Body {
	body := e.makeBody(data, size, mime, encoding)
	if body == nil || len(decoded) == 0 {
		return body
	}
	text, preview := decodePreview(decoded, "", "application/json")
	if !text {
		return body
	}
	body.Preview = preview
	body.Decrypted = true
	body.DecodedMime = "application/json; charset=utf-8"
	return body
}

func decodePreview(data []byte, encoding, mime string) (bool, string) {
	if len(data) == 0 {
		return false, ""
	}
	if strings.EqualFold(strings.TrimSpace(encoding), "br") ||
		strings.EqualFold(strings.TrimSpace(encoding), "zstd") {
		return false, ""
	}
	raw := blob.DecodeLimited(data, encoding, 64<<10)
	if len(raw) == 0 {
		return false, ""
	}
	if blob.LooksBinary(raw) {
		return false, ""
	}
	if !isTextMime(mime) && !looksLikeText(raw) {
		return false, ""
	}
	raw = trimUTF8(raw)
	if len(raw) > 2048 {
		raw = raw[:2048]
	}
	raw = trimUTF8(raw)
	if !utf8Valid(raw) {
		return false, ""
	}
	return true, string(raw)
}

// trimUTF8 去掉截断处不完整的 UTF-8 尾字节，避免预览整段失效。
func trimUTF8(data []byte) []byte {
	for len(data) > 0 && !utf8Valid(data) {
		data = data[:len(data)-1]
	}
	return data
}

func isTextMime(mime string) bool {
	mime = strings.ToLower(mime)
	return strings.HasPrefix(mime, "text/") ||
		strings.Contains(mime, "json") ||
		strings.Contains(mime, "javascript") ||
		strings.Contains(mime, "xml") ||
		strings.Contains(mime, "x-www-form-urlencoded") ||
		strings.Contains(mime, "graphql") ||
		strings.Contains(mime, "svg")
}

func looksLikeText(data []byte) bool {
	if bytes.IndexByte(data, 0) >= 0 {
		return false
	}
	kind := http.DetectContentType(data)
	return strings.HasPrefix(kind, "text/") || strings.Contains(kind, "json") || strings.Contains(kind, "xml")
}

func requestPath(r *http.Request) string {
	path := r.URL.RequestURI()
	if path == "" {
		return "/"
	}
	return path
}

func requestHeaders(r *http.Request) flow.Headers {
	return requestHeadersFrom(r.Header, r.Host)
}

func requestHeadersFrom(header http.Header, host string) flow.Headers {
	headers := headersFrom(header)
	if host != "" {
		headers = append(headers, flow.Header{Name: "Host", Value: host})
	}
	return headers
}

func responseHeaders(header http.Header) flow.Headers {
	return headersFrom(header)
}

func headersFrom(header http.Header) flow.Headers {
	names := make([]string, 0, len(header))
	for name := range header {
		names = append(names, name)
	}
	sort.Strings(names)

	var out flow.Headers
	for _, name := range names {
		for _, value := range header[name] {
			out = append(out, flow.Header{Name: name, Value: value})
		}
	}
	return out
}

func copyHeader(dst, src http.Header) {
	for name, values := range src {
		for _, value := range values {
			dst.Add(name, value)
		}
	}
}

func removeHopByHop(header http.Header) {
	connection := header.Get("Connection")
	for _, name := range []string{
		"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
		"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
	} {
		header.Del(name)
	}
	if connection != "" {
		for _, token := range strings.Split(connection, ",") {
			if token = strings.TrimSpace(token); token != "" {
				header.Del(token)
			}
		}
	}
}

func splitRemote(remote string) (string, int) {
	host, port, err := net.SplitHostPort(remote)
	if err != nil {
		return remote, 0
	}
	return host, parsePort(port, 0)
}

func hostForURL(host string, port int, scheme string) string {
	if (scheme == "http" && port == 80) || (scheme == "https" && port == 443) {
		if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
			return "[" + host + "]"
		}
		return host
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

func isNetworkError(err error) bool {
	var opErr *net.OpError
	return errors.As(err, &opErr)
}

type traceState struct {
	started     time.Time
	dnsStart    time.Time
	dnsDone     time.Time
	connectFrom time.Time
	connectDone time.Time
	tlsStart    time.Time
	tlsDone     time.Time
	firstByte   time.Time
	gotConn     httptrace.GotConnInfo
	tlsState    *tls.ConnectionState
}

func (t *traceState) clientTrace() *httptrace.ClientTrace {
	return &httptrace.ClientTrace{
		DNSStart: func(httptrace.DNSStartInfo) {
			t.dnsStart = time.Now()
		},
		DNSDone: func(httptrace.DNSDoneInfo) {
			t.dnsDone = time.Now()
		},
		ConnectStart: func(_, _ string) {
			t.connectFrom = time.Now()
		},
		ConnectDone: func(_, _ string, _ error) {
			t.connectDone = time.Now()
		},
		TLSHandshakeStart: func() {
			t.tlsStart = time.Now()
		},
		TLSHandshakeDone: func(state tls.ConnectionState, err error) {
			t.tlsDone = time.Now()
			if err == nil {
				s := state
				t.tlsState = &s
			}
		},
		GotConn: func(info httptrace.GotConnInfo) {
			t.gotConn = info
			if tlsConn, ok := info.Conn.(*tls.Conn); ok {
				state := tlsConn.ConnectionState()
				t.tlsState = &state
			}
		},
		GotFirstResponseByte: func() {
			t.firstByte = time.Now()
		},
	}
}

func (t *traceState) timing(end time.Time) *flow.Timing {
	total := end.Sub(t.started).Milliseconds()
	if total < 0 {
		total = 0
	}
	dnsMs := span(t.dnsStart, t.dnsDone)
	connectMs := span(t.connectFrom, t.connectDone)
	tlsMs := span(t.tlsStart, t.tlsDone)
	sendMs := int64(1)
	waitMs := int64(0)
	receiveMs := int64(0)
	if !t.firstByte.IsZero() {
		waitMs = t.firstByte.Sub(t.started).Milliseconds() - dnsMs - connectMs - tlsMs - sendMs
		if waitMs < 0 {
			waitMs = 0
		}
		receiveMs = end.Sub(t.firstByte).Milliseconds()
		if receiveMs < 0 {
			receiveMs = 0
		}
	}
	return &flow.Timing{
		DNSMs:     dnsMs,
		ConnectMs: connectMs,
		TLSMs:     tlsMs,
		SendMs:    sendMs,
		WaitMs:    waitMs,
		ReceiveMs: receiveMs,
		TotalMs:   total,
	}
}

func (t *traceState) remoteIP() string {
	if t.gotConn.Conn == nil {
		return ""
	}
	addr := t.gotConn.Conn.RemoteAddr()
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}

func (t *traceState) tlsInfo(host string, insecure bool) *flow.TLSInfo {
	if t.tlsState == nil {
		return nil
	}
	state := t.tlsState
	info := &flow.TLSInfo{
		Version:     tlsVersionName(state.Version),
		CipherSuite: tls.CipherSuiteName(state.CipherSuite),
		SNI:         host,
		ALPN:        state.NegotiatedProtocol,
		Verified:    !insecure && len(state.VerifiedChains) > 0,
	}
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		sans := append([]string(nil), cert.DNSNames...)
		for _, ip := range cert.IPAddresses {
			sans = append(sans, ip.String())
		}
		info.Cert = &flow.Certificate{
			Subject:   cert.Subject.String(),
			Issuer:    cert.Issuer.String(),
			NotBefore: cert.NotBefore.Format(time.RFC3339),
			NotAfter:  cert.NotAfter.Format(time.RFC3339),
			SANs:      sans,
		}
	}
	return info
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS13:
		return "TLS1.3"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS10:
		return "TLS1.0"
	default:
		return fmt.Sprintf("0x%04x", version)
	}
}

func span(start, end time.Time) int64 {
	if start.IsZero() || end.IsZero() || end.Before(start) {
		return 0
	}
	return end.Sub(start).Milliseconds()
}
