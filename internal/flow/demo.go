package flow

import (
	"fmt"
	"math/rand"
	"strings"
	"time"
)

type demoEndpoint struct {
	Scheme   string
	Host     string
	Port     int
	Path     string
	Method   string
	Status   int
	Mime     string
	ReqBody  string
	RespBody string
	Slow     bool
	Tags     []string
	Note     string
}

var demoEndpoints = []demoEndpoint{
	{"https", "api.example.com", 443, "/v1/users/42", "GET", 200, "application/json", "", `{"id":42,"name":"张三","role":"admin","active":true}` + "\n", false, nil, ""},
	{"https", "api.example.com", 443, "/v1/users/42", "PATCH", 200, "application/json", `{"name":"李四","active":false}`, `{"id":42,"name":"李四","active":false}` + "\n", false, nil, ""},
	{"https", "api.example.com", 443, "/v1/orders", "POST", 201, "application/json", `{"sku":"SC-001","quantity":2,"remark":"尽快发货"}`, `{"orderId":"ord_8f2c1a","status":"created"}` + "\n", false, []string{"important"}, "订单创建成功"},
	{"https", "api.example.com", 443, "/v1/orders/9001", "GET", 404, "application/json", "", `{"code":404,"message":"order not found"}` + "\n", false, nil, ""},
	{"https", "api.example.com", 443, "/v1/session", "GET", 401, "application/json", "", `{"code":401,"message":"token expired"}` + "\n", false, []string{"auth"}, "检查登录态"},
	{"https", "api.example.com", 443, "/v1/reports/export", "GET", 500, "application/json", "", `{"code":500,"message":"report service unavailable"}` + "\n", true, []string{"error"}, "与后端联调中"},
	{"https", "api.example.com", 443, "/v1/search?q=scanner&page=2", "GET", 200, "application/json", "", `{"total":38,"items":[{"id":7,"title":"Traffic Scanner"}]}` + "\n", false, nil, ""},
	{"https", "cdn.example.com", 443, "/assets/app.9f2c1.js", "GET", 200, "application/javascript", "", "/* bundled app */\nconsole.log('scanning demo');\n", false, nil, ""},
	{"https", "cdn.example.com", 443, "/assets/style.css", "GET", 200, "text/css", "", ":root{--bg:#0b0f14;--fg:#e6edf3}\nbody{margin:0;background:var(--bg);color:var(--fg)}\n", false, nil, ""},
	{"https", "cdn.example.com", 443, "/images/hero.webp", "GET", 200, "image/webp", "", "", false, nil, ""},
	{"https", "cdn.example.com", 443, "/assets/missing.js", "GET", 404, "text/plain", "", "not found\n", false, nil, ""},
	{"https", "auth.example.com", 443, "/oauth/token", "POST", 200, "application/json", `{"grant_type":"password","username":"demo"}`, `{"access_token":"eyJhbGciOi...","token_type":"Bearer","expires_in":3600}` + "\n", false, []string{"auth"}, ""},
	{"https", "auth.example.com", 443, "/oauth/introspect", "POST", 401, "application/json", `{"token":"expired"}`, `{"active":false}` + "\n", false, []string{"auth"}, ""},
	{"https", "api.other.dev", 443, "/v1/health", "GET", 200, "text/plain", "", "ok\n", false, nil, ""},
	{"https", "api.other.dev", 443, "/v1/slow-query", "GET", 200, "application/json", "", `{"rows":1280,"cached":false}` + "\n", true, []string{"slow"}, "慢查询"},
	{"wss", "ws.example.com", 443, "/socket", "GET", 101, "text/plain", "", "", false, nil, ""},
	{"http", "legacy.example.net", 80, "/status", "GET", 200, "application/json", "", `{"status":"ok","region":"cn-east-1"}` + "\n", false, nil, ""},
}

var serverIPs = map[string]string{
	"api.example.com":    "93.184.216.34",
	"cdn.example.com":    "151.101.1.69",
	"auth.example.com":   "104.18.32.7",
	"api.other.dev":      "203.0.113.24",
	"ws.example.com":     "198.51.100.8",
	"legacy.example.net": "192.0.2.44",
}

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 Safari/605.1.15",
	"curl/8.7.1",
	"Scanning-Demo/0.1",
}

var clientApps = []string{"chrome.exe", "Code.exe", "curl", "node.exe"}

func Generate(n int) []*Flow {
	if n <= 0 {
		return nil
	}
	out := make([]*Flow, 0, n)
	now := time.Now()
	for i := 0; i < n; i++ {
		out = append(out, generateOne(now))
	}
	return out
}

func generateOne(now time.Time) *Flow {
	ep := demoEndpoints[rand.Intn(len(demoEndpoints))]
	mode := ModeProxy
	if rand.Intn(10) == 0 {
		mode = ModePCAP
	}

	duration := int64(rand.Intn(220) + 18)
	if ep.Slow {
		duration = int64(rand.Intn(1200) + 700)
	}

	dns := int64(rand.Intn(12) + 1)
	connect := int64(rand.Intn(28) + 4)
	tlsMs := int64(0)
	if ep.Scheme == "https" || ep.Scheme == "wss" {
		tlsMs = int64(rand.Intn(45) + 8)
	}
	send := int64(rand.Intn(6) + 1)
	wait := duration
	if tlsMs > 0 {
		wait = duration - dns - connect - tlsMs - send
	} else {
		wait = duration - dns - connect - send
	}
	if wait < 1 {
		wait = 1
	}
	receive := int64(rand.Intn(20) + 2)
	total := dns + connect + tlsMs + send + wait + receive
	if total > duration {
		duration = total
	}

	started := now.Add(-time.Duration(rand.Intn(900)) * time.Second)
	completed := started.Add(time.Duration(total) * time.Millisecond)

	respSize := int64(len(ep.RespBody))
	reqSize := int64(len(ep.ReqBody) + 180)
	if ep.Mime == "image/webp" {
		respSize = int64(rand.Intn(180_000) + 24_000)
	}
	if ep.Mime == "application/javascript" {
		respSize = int64(rand.Intn(70_000) + 8_000)
	}
	if ep.Status == 404 || ep.Status == 401 {
		respSize = int64(len(ep.RespBody))
	}

	reqHeaders := Headers{
		{Name: "Host", Value: ep.Host},
		{Name: "User-Agent", Value: userAgents[rand.Intn(len(userAgents))]},
		{Name: "Accept", Value: "application/json, text/plain, */*"},
		{Name: "Accept-Encoding", Value: "gzip, br"},
	}
	if ep.ReqBody != "" {
		reqHeaders = reqHeaders.Set("Content-Type", "application/json")
	}
	if ep.Host == "auth.example.com" {
		reqHeaders = reqHeaders.Set("Authorization", "Bearer demo-token")
	}
	if ep.Host == "api.example.com" {
		reqHeaders = reqHeaders.Set("Cookie", "session=demo-session; theme=dark")
	}

	respHeaders := Headers{
		{Name: "Content-Type", Value: ep.Mime},
		{Name: "Content-Length", Value: fmt.Sprintf("%d", respSize)},
		{Name: "Server", Value: "nginx/1.27.2"},
		{Name: "Cache-Control", Value: "no-store"},
		{Name: "Date", Value: time.Now().UTC().Format(time.RFC1123)},
	}
	if ep.Host == "cdn.example.com" && ep.Status == 200 {
		respHeaders = respHeaders.Set("Cache-Control", "public, max-age=31536000, immutable")
		respHeaders = respHeaders.Set("Etag", `"9f2c1a7b"`)
	}

	respBody := &Body{
		Size:         respSize,
		CapturedSize: int64(len(ep.RespBody)),
		Mime:         ep.Mime,
		Encoding:     "identity",
		Text:         ep.RespBody != "",
		Preview:      previewText(ep.RespBody),
	}
	if ep.Mime == "image/webp" {
		respBody.Text = false
		respBody.Preview = ""
		respBody.Truncated = true
	}
	if ep.Mime == "application/javascript" && respSize > int64(len(ep.RespBody)) {
		respBody.Truncated = true
	}

	var reqBody *Body
	if ep.ReqBody != "" {
		reqBody = &Body{
			Size:         int64(len(ep.ReqBody)),
			CapturedSize: int64(len(ep.ReqBody)),
			Mime:         "application/json",
			Encoding:     "identity",
			Text:         true,
			Preview:      ep.ReqBody,
		}
	}

	f := &Flow{
		Mode:       mode,
		State:      StateCompleted,
		Scheme:     ep.Scheme,
		Host:       ep.Host,
		Port:       ep.Port,
		Method:     ep.Method,
		Path:       ep.Path,
		StatusCode: ep.Status,
		Mime:       ep.Mime,
		ReqSize:    reqSize,
		RespSize:   respSize,
		DurationMs: total,
		Client: ClientInfo{
			IP:     "127.0.0.1",
			Port:   49152 + rand.Intn(16000),
			App:    clientApps[rand.Intn(len(clientApps))],
			PID:    1000 + rand.Intn(9000),
			Origin: "demo",
		},
		Server: ServerInfo{
			IP:   serverIPs[ep.Host],
			Port: ep.Port,
			Name: ep.Host,
		},
		Request: &Message{
			HTTPVersion: "HTTP/1.1",
			Headers:     reqHeaders,
			Body:        reqBody,
		},
		Response: &Message{
			HTTPVersion: "HTTP/1.1",
			Headers:     respHeaders,
			Body:        respBody,
		},
		Timing: &Timing{
			DNSMs:     dns,
			ConnectMs: connect,
			TLSMs:     tlsMs,
			SendMs:    send,
			WaitMs:    wait,
			ReceiveMs: receive,
			TotalMs:   total,
		},
		Tags:        cloneStrings(ep.Tags),
		Note:        ep.Note,
		Pinned:      rand.Intn(20) == 0,
		StartedAt:   started,
		CompletedAt: &completed,
	}

	if f.Tags == nil {
		f.Tags = []string{}
	}

	if ep.Scheme == "https" || ep.Scheme == "wss" {
		f.TLS = &TLSInfo{
			Version:     "TLS1.3",
			CipherSuite: "TLS_AES_128_GCM_SHA256",
			SNI:         ep.Host,
			ALPN:        "h2",
			Verified:    true,
			Cert: &Certificate{
				Subject:   "CN=" + ep.Host,
				Issuer:    "CN=DigiCert TLS RSA SHA256 2020 CA1",
				NotBefore: time.Now().Add(-90 * 24 * time.Hour).Format(time.RFC3339),
				NotAfter:  time.Now().Add(275 * 24 * time.Hour).Format(time.RFC3339),
				SANs:      []string{ep.Host, "*." + strings.TrimPrefix(ep.Host, "api.")},
			},
		}
	}

	return f
}

func previewText(s string) string {
	const max = 1024
	if len(s) <= max {
		return s
	}
	return s[:max] + "\n…"
}
