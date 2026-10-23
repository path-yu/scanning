package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"scanning/internal/config"
	"scanning/internal/event"
	"scanning/internal/flow"
	"scanning/internal/store"
)

type listEnvelope struct {
	Data  []flow.Summary `json:"data"`
	Meta  listMeta       `json:"meta"`
	Error *apiError      `json:"error"`
}

type listMeta struct {
	Total      int    `json:"total"`
	NextCursor string `json:"nextCursor"`
	HasMore    bool   `json:"hasMore"`
	RequestID  string `json:"requestId"`
}

type flowEnvelope struct {
	Data  flow.Flow `json:"data"`
	Error *apiError `json:"error"`
}

func newTestServer(t *testing.T, dev bool) (*httptest.Server, *store.Ring) {
	t.Helper()
	cfg := config.Default()
	cfg.Demo.Enabled = true

	session := flow.Session{
		ID:        "session-test",
		Name:      "测试会话",
		Mode:      flow.ModeMixed,
		CreatedAt: time.Now(),
	}
	st := store.NewRing(100, session.ID)
	for _, f := range flow.Generate(6) {
		st.Add(f)
	}
	// 固定一条便于断言的数据。
	known := &flow.Flow{
		Scheme:     "https",
		Host:       "fixed.example.com",
		Port:       443,
		Method:     "POST",
		Path:       "/v1/fixed",
		StatusCode: 500,
		Mime:       "application/json",
		ReqSize:    20,
		RespSize:   30,
		DurationMs: 123,
		State:      flow.StateCompleted,
		Mode:       flow.ModeProxy,
		Request:    &flow.Message{HTTPVersion: "HTTP/1.1", Headers: flow.Headers{{Name: "Content-Type", Value: "application/json"}}},
		Response: &flow.Message{HTTPVersion: "HTTP/1.1", Headers: flow.Headers{{Name: "Content-Type", Value: "application/json"}},
			Body: &flow.Body{Size: 30, CapturedSize: 30, Mime: "application/json", Text: true, Preview: `{"error":"boom"}`}},
		StartedAt: time.Now(),
	}
	known = st.Add(known)

	hub := event.NewHub(session.ID)
	s := New(Options{
		Config:  cfg,
		Store:   st,
		Hub:     hub,
		Token:   "test-token",
		Session: session,
		Dev:     dev,
	})
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	t.Cleanup(hub.Close)
	return ts, st
}

func getJSON(t *testing.T, url string, dst any, headers map[string]string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if dst != nil {
		if err := json.Unmarshal(data, dst); err != nil {
			t.Fatalf("decode %s: %v (%s)", url, err, data)
		}
	}
	return resp.StatusCode
}

func TestListAndFilterFlows(t *testing.T) {
	ts, _ := newTestServer(t, true)

	var list listEnvelope
	status := getJSON(t, ts.URL+"/api/v1/flows?order=asc&limit=3", &list, nil)
	if status != http.StatusOK {
		t.Fatalf("status = %d", status)
	}
	if len(list.Data) != 3 || !list.Meta.HasMore || list.Meta.Total < 7 {
		t.Fatalf("unexpected list: %+v", list)
	}
	if list.Data[0].Seq != 1 {
		t.Fatalf("first seq = %d", list.Data[0].Seq)
	}

	var filtered listEnvelope
	status = getJSON(t, ts.URL+"/api/v1/flows?filter=host:fixed.example.com", &filtered, nil)
	if status != http.StatusOK || len(filtered.Data) != 1 {
		t.Fatalf("filtered status=%d len=%d", status, len(filtered.Data))
	}
	if filtered.Data[0].StatusCode != 500 {
		t.Fatalf("status code = %d", filtered.Data[0].StatusCode)
	}
}

func TestGetPatchAndBody(t *testing.T) {
	ts, st := newTestServer(t, true)
	items, _, _ := st.List(nil, 0, 1, false)
	id := items[0].ID

	var got flowEnvelope
	if status := getJSON(t, ts.URL+"/api/v1/flows/"+id, &got, nil); status != http.StatusOK {
		t.Fatalf("get status = %d", status)
	}
	if got.Data.ID != id {
		t.Fatalf("got id = %s", got.Data.ID)
	}

	body := `{"note":"checked","tags":["m0"],"pinned":true}`
	req, _ := http.NewRequest(http.MethodPatch, ts.URL+"/api/v1/flows/"+id, bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		t.Fatalf("patch status=%d body=%s", resp.StatusCode, data)
	}

	var patched flowEnvelope
	getJSON(t, ts.URL+"/api/v1/flows/"+id, &patched, nil)
	if patched.Data.Note != "checked" || !patched.Data.Pinned {
		t.Fatalf("patch not applied: %+v", patched.Data)
	}
}

func TestDemoAndClear(t *testing.T) {
	ts, _ := newTestServer(t, true)

	var before listEnvelope
	getJSON(t, ts.URL+"/api/v1/flows", &before, nil)

	resp, err := http.Post(ts.URL+"/api/v1/demo/flows", "application/json", bytes.NewReader([]byte(`{"count":3}`)))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("demo status = %d", resp.StatusCode)
	}

	var after listEnvelope
	getJSON(t, ts.URL+"/api/v1/flows", &after, nil)
	if after.Meta.Total != before.Meta.Total+3 {
		t.Fatalf("total before=%d after=%d", before.Meta.Total, after.Meta.Total)
	}

	req, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/v1/flows?confirm=true", nil)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("clear status = %d", resp.StatusCode)
	}

	var empty listEnvelope
	getJSON(t, ts.URL+"/api/v1/flows", &empty, nil)
	if empty.Meta.Total != 0 {
		t.Fatalf("after clear total = %d", empty.Meta.Total)
	}
}

func TestAuthRequired(t *testing.T) {
	ts, _ := newTestServer(t, false)
	url := ts.URL + "/api/v1/flows"

	if status := getJSON(t, url, nil, nil); status != http.StatusUnauthorized {
		t.Fatalf("without token status = %d", status)
	}
	if status := getJSON(t, url, nil, map[string]string{"Authorization": "Bearer test-token"}); status != http.StatusOK {
		t.Fatalf("with token status = %d", status)
	}
}

func TestBodyPreview(t *testing.T) {
	ts, st := newTestServer(t, true)
	items, _, _ := st.List(nil, 0, 50, false)
	var target *flow.Flow
	for _, item := range items {
		if item.Response != nil && item.Response.Body != nil && item.Response.Body.Preview != "" {
			target = item
			break
		}
	}
	if target == nil {
		t.Skip("no body preview in demo data")
	}

	req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/api/v1/flows/%s/body?direction=response", ts.URL, target.ID), nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("body status = %d", resp.StatusCode)
	}
	data, _ := io.ReadAll(resp.Body)
	if len(data) == 0 {
		t.Fatal("empty body")
	}
}
