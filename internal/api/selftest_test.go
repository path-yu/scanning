package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"scanning/internal/blob"
	"scanning/internal/config"
	"scanning/internal/event"
	"scanning/internal/flow"
	"scanning/internal/mitm"
	"scanning/internal/proxy"
	"scanning/internal/store"
)

func TestParseSelfTestTarget(t *testing.T) {
	cases := []struct {
		raw   string
		host  string
		port  string
		wantE bool
	}{
		{raw: "", host: "example.com", port: "443"},
		{raw: "example.com", host: "example.com", port: "443"},
		{raw: "example.com:8443", host: "example.com", port: "8443"},
		{raw: "https://example.com/path?q=1", host: "example.com", port: "443"},
		{raw: "https://example.com:9443/path", host: "example.com", port: "9443"},
		{raw: "127.0.0.1:8899", host: "127.0.0.1", port: "8899"},
		{raw: "http://127.0.0.1:8080/x", host: "127.0.0.1", port: "8080"},
		{raw: "exa mple.com", wantE: true},
		{raw: "example.com:0", wantE: true},
		{raw: "example.com:70000", wantE: true},
	}
	for _, tc := range cases {
		host, port, display, err := parseSelfTestTarget(tc.raw)
		if tc.wantE {
			if err == nil {
				t.Fatalf("%q 期望报错，得到 %s:%s (%s)", tc.raw, host, port, display)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%q 解析失败: %v", tc.raw, err)
		}
		if host != tc.host || port != tc.port {
			t.Fatalf("%q => %s:%s，期望 %s:%s", tc.raw, host, port, tc.host, tc.port)
		}
		if display == "" {
			t.Fatalf("%q 缺少展示地址", tc.raw)
		}
	}
}

func TestSelfTestThroughMITMProxy(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("selftest-ok"))
	}))
	defer upstream.Close()
	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}

	certs, err := mitm.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	cfg := config.Default()
	cfg.Demo.Enabled = false
	session := flow.Session{ID: "session-selftest", Name: "自检会话", Mode: flow.ModeProxy, CreatedAt: time.Now()}
	st := store.NewRing(100, session.ID)
	hub := event.NewHub(session.ID)
	t.Cleanup(hub.Close)
	blobs, err := blob.New("")
	if err != nil {
		t.Fatal(err)
	}

	pcfg := proxy.FromConfig(cfg.Proxy)
	pcfg.Addr = "127.0.0.1:0"
	pcfg.MITM = true
	pcfg.UpstreamInsecureSkipVerify = true
	engine := proxy.New(pcfg, proxy.Deps{
		Certs:     certs,
		Store:     st,
		Hub:       hub,
		Blobs:     blobs,
		SessionID: session.ID,
	})
	if err := engine.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = engine.Stop(ctx)
	})

	s := New(Options{
		Config:  cfg,
		Store:   st,
		Hub:     hub,
		Proxy:   engine,
		Certs:   certs,
		Blobs:   blobs,
		Token:   "test-token",
		Session: session,
		Dev:     true,
	})
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	status, data := doJSON(t, http.MethodPost, ts.URL+"/api/v1/system/selftest", map[string]any{"target": upstreamURL.Host})
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%s", status, data)
	}
	var envelope struct {
		Data selfTestResult `json:"data"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		t.Fatal(err)
	}
	result := envelope.Data
	if !result.OK {
		t.Fatalf("自检未通过: %+v", result)
	}
	if result.Target != "https://"+upstreamURL.Host+"/" {
		t.Fatalf("target = %q", result.Target)
	}
	names := make([]string, 0, len(result.Steps))
	for _, step := range result.Steps {
		names = append(names, step.Name)
		if step.Status != "pass" {
			t.Fatalf("步骤 %s 未通过: %+v", step.Name, step)
		}
	}
	want := []string{"proxy", "dns", "tcp", "tls", "http"}
	if len(names) != len(want) {
		t.Fatalf("steps = %v", names)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("steps = %v，期望 %v", names, want)
		}
	}
}

func TestSelfTestFailsWhenProxyStopped(t *testing.T) {
	certs, err := mitm.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Demo.Enabled = false
	session := flow.Session{ID: "session-selftest-stopped", Name: "自检会话", Mode: flow.ModeProxy, CreatedAt: time.Now()}
	st := store.NewRing(10, session.ID)
	hub := event.NewHub(session.ID)
	t.Cleanup(hub.Close)
	blobs, err := blob.New("")
	if err != nil {
		t.Fatal(err)
	}
	engine := proxy.New(proxy.FromConfig(cfg.Proxy), proxy.Deps{Certs: certs, Store: st, Hub: hub, Blobs: blobs, SessionID: session.ID})

	s := New(Options{
		Config:  cfg,
		Store:   st,
		Hub:     hub,
		Proxy:   engine,
		Certs:   certs,
		Blobs:   blobs,
		Session: session,
		Dev:     true,
	})
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	status, data := doJSON(t, http.MethodPost, ts.URL+"/api/v1/system/selftest", nil)
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%s", status, data)
	}
	var envelope struct {
		Data selfTestResult `json:"data"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Data.OK {
		t.Fatalf("代理未启动时不应通过: %+v", envelope.Data)
	}
	if len(envelope.Data.Steps) != 5 || envelope.Data.Steps[0].Status != "fail" {
		t.Fatalf("steps = %+v", envelope.Data.Steps)
	}
}
