package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"scanning/internal/blob"
	"scanning/internal/event"
	"scanning/internal/flow"
	"scanning/internal/mitm"
	"scanning/internal/rules"
	"scanning/internal/store"
)

func newM2Engine(t *testing.T) (*Engine, *store.Ring, *rules.Store, *blob.Store) {
	t.Helper()
	certs, err := mitm.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	st := store.NewRing(200, "session-m2")
	hub := event.NewHub("session-m2")
	t.Cleanup(hub.Close)
	blobs, err := blob.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ruleStore, err := rules.NewStore("")
	if err != nil {
		t.Fatal(err)
	}
	engine := New(Config{
		Addr:                       "127.0.0.1:0",
		MITM:                       true,
		UpstreamInsecureSkipVerify: true,
		MaxBodyBytes:               1 << 20,
		BreakpointTimeout:          5 * time.Second,
	}, Deps{
		Certs:     certs,
		Store:     st,
		Hub:       hub,
		Blobs:     blobs,
		Rules:     ruleStore,
		SessionID: "session-m2",
	})
	if err := engine.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = engine.Stop(context.Background()) })
	return engine, st, ruleStore, blobs
}

func proxyClient(engine *Engine) *http.Client {
	proxyURL, _ := url.Parse("http://" + engine.Status().Addr)
	return &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   10 * time.Second,
	}
}

func waitCompleted(t *testing.T, st *store.Ring, pathPrefix string) *flow.Flow {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, f := range st.All() {
			if strings.HasPrefix(f.Path, pathPrefix) && (f.State == flow.StateCompleted || f.State == flow.StateFailed) {
				return f
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("flow %s not completed", pathPrefix)
	return nil
}

func waitPaused(t *testing.T, st *store.Ring, pathPrefix string) *flow.Flow {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, f := range st.All() {
			if strings.HasPrefix(f.Path, pathPrefix) && f.State == flow.StatePaused {
				return f
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("flow %s not paused", pathPrefix)
	return nil
}

func TestRuleMockAndBlock(t *testing.T) {
	var upstreamHits atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		_, _ = w.Write([]byte("upstream"))
	}))
	defer upstream.Close()

	engine, st, ruleStore, _ := newM2Engine(t)
	body := `{"mocked":true}`
	_, err := ruleStore.Save(rules.Rule{
		Name:     "mock api",
		Enabled:  true,
		Priority: 1,
		Phase:    rules.PhaseRequest,
		Match:    rules.Match{Host: "127.0.0.1", Path: "/mock"},
		Actions: []rules.Action{{
			Type:    rules.ActionMock,
			Status:  201,
			Headers: []flow.Header{{Name: "Content-Type", Value: "application/json"}},
			Body:    &body,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ruleStore.Save(rules.Rule{
		Name:    "block admin",
		Enabled: true,
		Phase:   rules.PhaseRequest,
		Match:   rules.Match{Path: "/admin*"},
		Actions: []rules.Action{{Type: rules.ActionBlock}},
	}); err != nil {
		t.Fatal(err)
	}

	client := proxyClient(engine)
	resp, err := client.Get(upstream.URL + "/mock")
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 201 || string(payload) != body {
		t.Fatalf("mock response = %d %q", resp.StatusCode, payload)
	}
	if resp.Header.Get("X-Scanning-Mock") != "1" {
		t.Fatal("mock header missing")
	}
	if upstreamHits.Load() != 0 {
		t.Fatal("mock should not hit upstream")
	}

	blocked, err := client.Get(upstream.URL + "/admin/secret")
	if err != nil {
		t.Fatal(err)
	}
	blocked.Body.Close()
	if blocked.StatusCode != http.StatusForbidden {
		t.Fatalf("block status = %d", blocked.StatusCode)
	}
	if upstreamHits.Load() != 0 {
		t.Fatal("blocked request should not hit upstream")
	}

	f := waitCompleted(t, st, "/mock")
	if len(f.MatchedRules) != 1 || f.MatchedRules[0] != "mock api" {
		t.Fatalf("matched rules = %+v", f.MatchedRules)
	}
	if f.Response == nil || f.Response.Body == nil || f.Response.Body.Preview != body {
		t.Fatalf("mock body not captured: %+v", f.Response)
	}
}

func TestResponseRewriteRule(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"boom"}`))
	}))
	defer upstream.Close()

	engine, st, ruleStore, _ := newM2Engine(t)
	body := `{"rewritten":true}`
	if _, err := ruleStore.Save(rules.Rule{
		Name:     "rewrite 5xx",
		Enabled:  true,
		Phase:    rules.PhaseResponse,
		Priority: 1,
		Match:    rules.Match{Status: "5xx", Path: "/fail"},
		Actions:  []rules.Action{{Type: rules.ActionRewriteResponse, Status: 200, Body: &body}},
	}); err != nil {
		t.Fatal(err)
	}

	resp, err := proxyClient(engine).Get(upstream.URL + "/fail")
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(payload) != body {
		t.Fatalf("rewritten response = %d %q", resp.StatusCode, payload)
	}

	f := waitCompleted(t, st, "/fail")
	if f.StatusCode != 200 || f.Response == nil || f.Response.Body == nil || !strings.Contains(f.Response.Body.Preview, "rewritten") {
		t.Fatalf("flow not updated: %+v", f)
	}
}

func TestBreakpointResume(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("released"))
	}))
	defer upstream.Close()

	engine, st, ruleStore, _ := newM2Engine(t)
	if _, err := ruleStore.Save(rules.Rule{
		Name:    "pause echo",
		Enabled: true,
		Phase:   rules.PhaseRequest,
		Match:   rules.Match{Path: "/paused"},
		Actions: []rules.Action{{Type: rules.ActionPause}},
	}); err != nil {
		t.Fatal(err)
	}

	type result struct {
		status int
		body   string
		err    error
	}
	ch := make(chan result, 1)
	go func() {
		resp, err := proxyClient(engine).Get(upstream.URL + "/paused")
		if err != nil {
			ch <- result{err: err}
			return
		}
		payload, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		ch <- result{status: resp.StatusCode, body: string(payload)}
	}()

	paused := waitPaused(t, st, "/paused")
	if !paused.Breakpoint {
		t.Fatal("breakpoint flag not set")
	}
	if !engine.Resume(paused.ID, ResumeCommand{Action: ResumeForward}) {
		t.Fatal("resume failed")
	}

	select {
	case got := <-ch:
		if got.err != nil {
			t.Fatal(got.err)
		}
		if got.status != 200 || got.body != "released" {
			t.Fatalf("result = %+v", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("request did not continue after resume")
	}

	f := waitCompleted(t, st, "/paused")
	if !f.Breakpoint || f.State != flow.StateCompleted {
		t.Fatalf("completed flow = %+v", f)
	}
}

func TestReplayAndFullBody(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		payload, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"method":"` + r.Method + `","path":"` + r.URL.RequestURI() + `","body":"` + string(payload) + `","pad":"` + strings.Repeat("x", 6000) + `"}`))
	}))
	defer upstream.Close()

	engine, st, _, blobs := newM2Engine(t)
	client := proxyClient(engine)
	resp, err := client.Get(upstream.URL + "/source")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(resp.Body)
	resp.Body.Close()

	src := waitCompleted(t, st, "/source")
	if src.Response == nil || src.Response.Body == nil {
		t.Fatal("source response missing")
	}
	if src.Response.Body.Ref == "" {
		t.Fatal("full body ref missing")
	}
	full, err := blobs.Get(src.Response.Body.Ref)
	if err != nil {
		t.Fatal(err)
	}
	if len(full) < 6000 {
		t.Fatalf("full body len = %d", len(full))
	}
	if len(src.Response.Body.Preview) > 2048 {
		t.Fatalf("preview too long: %d", len(src.Response.Body.Preview))
	}

	replayBody := `{"replayed":1}`
	replayed, err := engine.Replay(context.Background(), src, ReplayOverrides{
		Method: "POST",
		URL:    upstream.URL + "/replay?x=1",
		Body:   &replayBody,
	})
	if err != nil {
		t.Fatal(err)
	}
	if replayed.ReplayedFrom != src.ID || replayed.StatusCode != 200 {
		t.Fatalf("replayed = %+v", replayed)
	}
	if replayed.Response == nil || replayed.Response.Body == nil || !strings.Contains(replayed.Response.Body.Preview, `"method":"POST"`) {
		t.Fatalf("replay response = %+v", replayed.Response)
	}
	if !strings.Contains(replayed.Response.Body.Preview, `/replay?x=1`) {
		t.Fatalf("replay URL not applied: %s", replayed.Response.Body.Preview)
	}
	if replayed.Request == nil || replayed.Request.Body == nil || replayed.Request.Body.Preview != replayBody {
		t.Fatalf("replay body = %+v", replayed.Request)
	}
}

func TestBreakpointResumeWithMutations(t *testing.T) {
	type seen struct {
		method string
		path   string
		header string
		body   string
	}
	seenCh := make(chan seen, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		payload, _ := io.ReadAll(r.Body)
		seenCh <- seen{method: r.Method, path: r.URL.RequestURI(), header: r.Header.Get("X-Mutated"), body: string(payload)}
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	engine, st, ruleStore, _ := newM2Engine(t)
	if _, err := ruleStore.Save(rules.Rule{
		Name:    "pause mutate",
		Enabled: true,
		Phase:   rules.PhaseRequest,
		Match:   rules.Match{Path: "/mutate"},
		Actions: []rules.Action{{Type: rules.ActionPause}},
	}); err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{}, 1)
	go func() {
		resp, err := proxyClient(engine).Get(upstream.URL + "/mutate")
		if err == nil {
			_, _ = io.ReadAll(resp.Body)
			resp.Body.Close()
		}
		done <- struct{}{}
	}()

	paused := waitPaused(t, st, "/mutate")
	body := "changed-body"
	if !engine.Resume(paused.ID, ResumeCommand{
		Action:  ResumeForward,
		Method:  "POST",
		Path:    "/mutated?x=1",
		Headers: []flow.Header{{Name: "X-Mutated", Value: "yes"}},
		Body:    &body,
	}) {
		t.Fatal("resume failed")
	}
	select {
	case got := <-seenCh:
		if got.method != "POST" || got.path != "/mutated?x=1" || got.header != "yes" || got.body != body {
			t.Fatalf("upstream saw %+v", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("upstream did not receive mutated request")
	}
	<-done
	f := waitCompleted(t, st, "/mutated")
	if f.Method != "POST" || f.Path != "/mutated?x=1" {
		t.Fatalf("flow = %+v", f)
	}
}

func TestResponseBreakpointMutation(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("original"))
	}))
	defer upstream.Close()

	engine, st, ruleStore, _ := newM2Engine(t)
	if _, err := ruleStore.Save(rules.Rule{
		Name:    "pause response",
		Enabled: true,
		Phase:   rules.PhaseResponse,
		Match:   rules.Match{Path: "/resp-pause"},
		Actions: []rules.Action{{Type: rules.ActionPause}},
	}); err != nil {
		t.Fatal(err)
	}

	type result struct {
		status int
		body   string
	}
	ch := make(chan result, 1)
	go func() {
		resp, err := proxyClient(engine).Get(upstream.URL + "/resp-pause")
		if err != nil {
			ch <- result{status: -1}
			return
		}
		payload, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		ch <- result{status: resp.StatusCode, body: string(payload)}
	}()

	paused := waitPaused(t, st, "/resp-pause")
	if paused.StatusCode != 200 {
		t.Fatalf("paused response status = %d", paused.StatusCode)
	}
	body := "mutated-response"
	if !engine.Resume(paused.ID, ResumeCommand{
		Action:  ResumeForward,
		Status:  201,
		Headers: []flow.Header{{Name: "X-Mutated", Value: "1"}},
		Body:    &body,
	}) {
		t.Fatal("resume failed")
	}
	select {
	case got := <-ch:
		if got.status != 201 || got.body != body {
			t.Fatalf("client got %+v", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("client did not receive mutated response")
	}
	f := waitCompleted(t, st, "/resp-pause")
	if f.StatusCode != 201 || f.Response == nil || f.Response.Body == nil || f.Response.Body.Preview != body {
		t.Fatalf("flow = %+v", f)
	}
}

func TestParseRemote(t *testing.T) {
	scheme, host, port, err := parseRemote("http://localhost:8080", "https", "example.com", 443)
	if err != nil || scheme != "http" || host != "localhost" || port != 8080 {
		t.Fatalf("got %s %s %d err=%v", scheme, host, port, err)
	}
	scheme, host, port, err = parseRemote("127.0.0.1:9000", "https", "example.com", 443)
	if err != nil || scheme != "https" || host != "127.0.0.1" || port != 9000 {
		t.Fatalf("got %s %s %d err=%v", scheme, host, port, err)
	}
	if _, _, _, err := parseRemote("ftp://x", "http", "", 80); err == nil {
		t.Fatal("expected error")
	}
}
