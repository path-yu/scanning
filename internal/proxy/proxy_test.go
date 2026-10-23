package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"scanning/internal/event"
	"scanning/internal/flow"
	"scanning/internal/mitm"
	"scanning/internal/store"
)

func TestHTTPProxyCapturesFlow(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Request-Id", "upstream-1")
		_, _ = w.Write([]byte(`{"ok":true,"path":"` + r.URL.Path + `"}`))
	}))
	defer upstream.Close()

	engine, st := newTestEngine(t)
	defer engine.Stop(context.Background())

	proxyURL, _ := url.Parse("http://" + engine.Status().Addr)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	resp, err := client.Get(upstream.URL + "/plain?x=1")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), `"ok":true`) {
		t.Fatalf("unexpected body: %s", body)
	}
	if resp.Header.Get("X-Request-Id") != "upstream-1" {
		t.Fatalf("response header lost: %v", resp.Header)
	}

	f := waitFlow(t, st)
	if f.Host != "127.0.0.1" || f.StatusCode != 200 || f.Method != "GET" {
		t.Fatalf("unexpected flow: %+v", f)
	}
	if f.Response == nil || f.Response.Body == nil || !strings.Contains(f.Response.Body.Preview, `"ok":true`) {
		t.Fatalf("response body not captured: %+v", f.Response)
	}
	if f.TLS != nil {
		t.Fatalf("plain HTTP flow should not have TLS info")
	}
	if f.Path != "/plain?x=1" {
		t.Fatalf("path = %q", f.Path)
	}
}

func TestMITMProxyDecryptsAndCaptures(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"secret":"decrypted"}`))
	}))
	defer upstream.Close()

	engine, st := newTestEngine(t)
	defer engine.Stop(context.Background())

	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(engine.certs.CAPEM()) {
		t.Fatal("append CA failed")
	}
	proxyURL, _ := url.Parse("http://" + engine.Status().Addr)
	client := &http.Client{Transport: &http.Transport{
		Proxy:             http.ProxyURL(proxyURL),
		ForceAttemptHTTP2: false,
		TLSClientConfig:   &tls.Config{RootCAs: roots},
	}}
	resp, err := client.Get(upstream.URL + "/secure")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "decrypted") {
		t.Fatalf("unexpected body: %s", body)
	}

	f := waitFlow(t, st)
	if f.StatusCode != 200 || f.Scheme != "https" {
		t.Fatalf("unexpected flow: %+v", f)
	}
	if f.TLS == nil || f.TLS.Version == "" {
		t.Fatalf("TLS info missing: %+v", f.TLS)
	}
	if f.Response == nil || f.Response.Body == nil || !strings.Contains(f.Response.Body.Preview, "decrypted") {
		t.Fatalf("decrypted body not captured: %+v", f.Response)
	}
	if f.Server.IP == "" {
		t.Fatalf("server IP missing: %+v", f.Server)
	}
}

func newTestEngine(t *testing.T) (*Engine, *store.Ring) {
	t.Helper()
	certs, err := mitm.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	st := store.NewRing(100, "session-test")
	hub := event.NewHub("session-test")
	t.Cleanup(hub.Close)
	engine := New(Config{
		Addr:                       "127.0.0.1:0",
		MITM:                       true,
		UpstreamInsecureSkipVerify: true,
		MaxBodyBytes:               1 << 20,
	}, Deps{
		Certs:     certs,
		Store:     st,
		Hub:       hub,
		SessionID: "session-test",
	})
	if err := engine.Start(); err != nil {
		t.Fatal(err)
	}
	return engine, st
}

func waitFlow(t *testing.T, st *store.Ring) *flow.Flow {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		all := st.All()
		if len(all) > 0 {
			return all[0]
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("flow not captured")
	return nil
}
