package proxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strconv"
	"strings"
	"time"

	"scanning/internal/flow"
)

type ReplayOverrides struct {
	Method  string        `json:"method,omitempty"`
	URL     string        `json:"url,omitempty"`
	Headers []flow.Header `json:"headers,omitempty"`
	Body    *string       `json:"body,omitempty"`
}

// Replay 使用代理自身的上游 Transport 重发一条已记录的请求，并生成新的 Flow。
func (e *Engine) Replay(ctx context.Context, src *flow.Flow, ov ReplayOverrides) (*flow.Flow, error) {
	if src == nil {
		return nil, errors.New("源 Flow 为空")
	}
	method := strings.ToUpper(strings.TrimSpace(ov.Method))
	if method == "" {
		method = src.Method
	}
	if method == "" {
		method = http.MethodGet
	}

	target, err := replayURL(src, ov.URL)
	if err != nil {
		return nil, err
	}

	headers := http.Header{}
	if ov.Headers != nil {
		for _, header := range ov.Headers {
			if strings.TrimSpace(header.Name) == "" {
				continue
			}
			headers.Add(header.Name, header.Value)
		}
	} else if src.Request != nil {
		for _, header := range src.Request.Headers {
			if strings.EqualFold(header.Name, "Host") {
				continue
			}
			headers.Add(header.Name, header.Value)
		}
	}
	removeHopByHop(headers)

	body := e.replayBody(src, ov)
	if body != nil {
		headers.Set("Content-Length", strconv.Itoa(len(body)))
	} else {
		headers.Del("Content-Length")
	}

	started := time.Now()
	reqBody := e.makeBody(body, int64(len(body)), headers.Get("Content-Type"), headers.Get("Content-Encoding"))
	f := &flow.Flow{
		Mode:         flow.ModeProxy,
		State:        flow.StateActive,
		Scheme:       target.Scheme,
		Host:         target.Hostname(),
		Port:         replayPort(target),
		Method:       method,
		Path:         target.RequestURI(),
		ReqSize:      int64(len(body)),
		Client:       flow.ClientInfo{Origin: "replay"},
		Server:       flow.ServerInfo{Port: replayPort(target), Name: target.Hostname()},
		Request:      &flow.Message{HTTPVersion: "HTTP/1.1", Headers: requestHeadersFrom(headers, target.Host), Body: reqBody},
		Tags:         []string{"replay"},
		ReplayedFrom: src.ID,
		StartedAt:    started,
	}
	f = e.store.Add(f)
	e.hub.Broadcast("flow.created", f.Summary())

	var bodyReader io.ReadCloser = http.NoBody
	if len(body) > 0 {
		bodyReader = io.NopCloser(bytes.NewReader(body))
	}
	req, err := http.NewRequestWithContext(ctx, method, target.String(), bodyReader)
	if err != nil {
		e.failFlow(f, "http", err, http.StatusBadGateway)
		return f, nil
	}
	req.Header = headers.Clone()
	req.Host = target.Host
	if body != nil {
		req.ContentLength = int64(len(body))
	}
	trace := &traceState{started: started}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace.clientTrace()))

	resp, err := e.transport.RoundTrip(req)
	if err != nil {
		e.failFlow(f, stageOf(err), err, http.StatusBadGateway)
		return f, nil
	}
	defer resp.Body.Close()

	maxCapture := int(e.cfg.MaxBodyBytes)
	if maxCapture <= 0 {
		maxCapture = 10 << 20
	}
	respHeaders := resp.Header.Clone()
	removeHopByHop(respHeaders)
	captured, readErr := readPrefix(resp.Body, maxCapture)
	if readErr != nil && len(captured) == 0 {
		e.failFlow(f, "read", readErr, http.StatusBadGateway)
		return f, nil
	}
	respCaptured := truncateBytes(captured, maxCapture)
	respSize := resp.ContentLength
	if respSize < 0 {
		respSize = int64(len(captured))
	}
	if respSize < int64(len(respCaptured)) {
		respSize = int64(len(respCaptured))
	}
	respMime := respHeaders.Get("Content-Type")
	f.StatusCode = resp.StatusCode
	f.Mime = respMime
	f.RespSize = respSize
	f.Response = &flow.Message{
		HTTPVersion: resp.Proto,
		Headers:     responseHeaders(respHeaders),
		Body:        e.makeBody(respCaptured, respSize, respMime, respHeaders.Get("Content-Encoding")),
	}
	if readErr != nil {
		f.Error = &flow.FlowError{Stage: "read", Code: "read_error", Message: readErr.Error()}
	}
	e.completeFlow(f, trace, target.Hostname(), replayPort(target), started)
	return f, nil
}

func (e *Engine) replayBody(src *flow.Flow, ov ReplayOverrides) []byte {
	if ov.Body != nil {
		return []byte(*ov.Body)
	}
	if src.Request == nil || src.Request.Body == nil {
		return nil
	}
	body := src.Request.Body
	if body.Ref != "" {
		if data, err := e.blobs.Get(body.Ref); err == nil {
			return data
		}
	}
	if body.Preview != "" && body.Text {
		return []byte(body.Preview)
	}
	return nil
}

func replayURL(src *flow.Flow, override string) (*url.URL, error) {
	override = strings.TrimSpace(override)
	if override != "" {
		if strings.Contains(override, "://") {
			u, err := url.Parse(override)
			if err != nil {
				return nil, err
			}
			if u.Scheme != "http" && u.Scheme != "https" {
				return nil, errors.New("只支持 http/https URL")
			}
			if u.Host == "" {
				return nil, errors.New("URL 缺少主机")
			}
			if u.Path == "" {
				u.Path = "/"
			}
			return u, nil
		}
		base, err := url.Parse(src.URL())
		if err != nil {
			return nil, err
		}
		ref, err := url.Parse(override)
		if err != nil {
			return nil, err
		}
		return base.ResolveReference(ref), nil
	}
	u, err := url.Parse(src.URL())
	if err != nil {
		return nil, err
	}
	if u.Host == "" {
		return nil, errors.New("源 Flow 缺少目标地址")
	}
	if u.Path == "" {
		u.Path = "/"
	}
	return u, nil
}

func replayPort(u *url.URL) int {
	if u.Port() != "" {
		return parsePort(u.Port(), defaultPortInt(u.Scheme))
	}
	return defaultPortInt(u.Scheme)
}
