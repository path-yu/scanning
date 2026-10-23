package proxy

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"scanning/internal/event"
	"scanning/internal/store"
)

func TestHTTPTransportUsesUpstreamProxy(t *testing.T) {
	var sawAbsolute atomic.Bool
	var sawAuth atomic.Bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAbsolute.Store(r.URL.IsAbs())
		sawAuth.Store(r.Header.Get("Proxy-Authorization") != "")
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("via-upstream"))
	}))
	defer upstream.Close()

	withAuth := strings.Replace(upstream.URL, "http://", "http://user:secret@", 1)
	engine, _ := newUpstreamTestEngine(t, withAuth)
	defer stopEngine(engine)

	req, err := http.NewRequest(http.MethodGet, "http://target.invalid/hello?x=1", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := engine.transport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "via-upstream" {
		t.Fatalf("body = %q", body)
	}
	if !sawAbsolute.Load() {
		t.Fatal("上游代理未收到绝对 URI")
	}
	if !sawAuth.Load() {
		t.Fatal("上游代理未收到 Basic 认证头")
	}
	if status := engine.Status().UpstreamProxy; status == "" || strings.Contains(status, "secret") {
		t.Fatalf("upstream status = %q，不应暴露密码", status)
	}
}

func TestDialTargetUsesUpstreamConnect(t *testing.T) {
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			conn, err := echo.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()

	connects := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "CONNECT only", http.StatusMethodNotAllowed)
			return
		}
		target, err := net.DialTimeout("tcp", r.Host, 3*time.Second)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer target.Close()
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "hijack unsupported", http.StatusInternalServerError)
			return
		}
		conn, buffered, err := hijacker.Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		if _, err := buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			return
		}
		if err := buffered.Flush(); err != nil {
			return
		}
		select {
		case connects <- r.Host:
		default:
		}
		go func() {
			_, _ = io.Copy(target, conn)
		}()
		_, _ = io.Copy(conn, target)
	}))
	defer upstream.Close()

	engine, _ := newUpstreamTestEngine(t, upstream.URL)
	defer stopEngine(engine)

	conn, err := engine.dialTarget(echo.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "ping" {
		t.Fatalf("echo = %q", buf)
	}
	select {
	case target := <-connects:
		if target != echo.Addr().String() {
			t.Fatalf("CONNECT target = %q，期望 %q", target, echo.Addr().String())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("上游代理未收到 CONNECT")
	}
}

func newUpstreamTestEngine(t *testing.T, upstream string) (*Engine, *store.Ring) {
	t.Helper()
	st := store.NewRing(10, "session-upstream")
	hub := event.NewHub("session-upstream")
	t.Cleanup(hub.Close)
	engine := New(Config{
		Addr:                       "127.0.0.1:0",
		MITM:                       true,
		UpstreamProxy:              upstream,
		UpstreamInsecureSkipVerify: true,
		MaxBodyBytes:               1 << 20,
	}, Deps{
		Store:     st,
		Hub:       hub,
		SessionID: "session-upstream",
	})
	return engine, st
}

func stopEngine(engine *Engine) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = engine.Stop(ctx)
}
