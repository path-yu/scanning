package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"scanning/internal/blob"
	"scanning/internal/config"
	"scanning/internal/event"
	"scanning/internal/flow"
	"scanning/internal/persist"
	"scanning/internal/rules"
	"scanning/internal/store"
)

func newM2Server(t *testing.T) (*httptest.Server, *store.Ring, *blob.Store) {
	t.Helper()
	cfg := config.Default()
	cfg.Demo.Enabled = false
	session := flow.Session{ID: "session-m2-api", Name: "M2 会话", Mode: flow.ModeMixed, CreatedAt: time.Now()}
	st := store.NewRing(100, session.ID)
	hub := event.NewHub(session.ID)
	t.Cleanup(hub.Close)
	blobs, err := blob.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ruleStore, err := rules.NewStore(filepath.Join(t.TempDir(), "rules.json"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := persist.Open(filepath.Join(t.TempDir(), "sessions.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	s := New(Options{
		Config:  cfg,
		Store:   st,
		Hub:     hub,
		Blobs:   blobs,
		Rules:   ruleStore,
		DB:      db,
		Token:   "test-token",
		Session: session,
		Dev:     true,
	})
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return ts, st, blobs
}

func doJSON(t *testing.T, method, url string, payload any) (int, []byte) {
	t.Helper()
	var body io.Reader
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		t.Fatal(err)
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, data
}

func TestRulesCRUD(t *testing.T) {
	ts, _, _ := newM2Server(t)

	rule := map[string]any{
		"name":     "mock users",
		"enabled":  true,
		"priority": 5,
		"phase":    "request",
		"match":    map[string]any{"path": "/users/*"},
		"actions":  []map[string]any{{"type": "mock", "status": 200, "body": "[]"}},
	}
	status, data := doJSON(t, http.MethodPost, ts.URL+"/api/v1/rules", rule)
	if status != http.StatusOK {
		t.Fatalf("create status=%d body=%s", status, data)
	}
	var created struct {
		Data rules.Rule `json:"data"`
	}
	if err := json.Unmarshal(data, &created); err != nil || created.Data.ID == "" {
		t.Fatalf("created = %s err=%v", data, err)
	}

	status, data = doJSON(t, http.MethodGet, ts.URL+"/api/v1/rules", nil)
	var list struct {
		Data []rules.Rule `json:"data"`
	}
	if err := json.Unmarshal(data, &list); err != nil || status != http.StatusOK || len(list.Data) != 1 {
		t.Fatalf("list status=%d data=%s err=%v", status, data, err)
	}

	rule["name"] = "updated"
	rule["id"] = created.Data.ID
	status, data = doJSON(t, http.MethodPut, ts.URL+"/api/v1/rules/"+created.Data.ID, rule)
	if status != http.StatusOK {
		t.Fatalf("update status=%d body=%s", status, data)
	}
	var updated struct {
		Data rules.Rule `json:"data"`
	}
	_ = json.Unmarshal(data, &updated)
	if updated.Data.Name != "updated" {
		t.Fatalf("updated = %s", data)
	}

	status, data = doJSON(t, http.MethodPost, ts.URL+"/api/v1/rules", map[string]any{"name": "", "phase": "request"})
	if status != http.StatusBadRequest {
		t.Fatalf("invalid rule status=%d body=%s", status, data)
	}

	status, _ = doJSON(t, http.MethodDelete, ts.URL+"/api/v1/rules/"+created.Data.ID, nil)
	if status != http.StatusOK {
		t.Fatalf("delete status=%d", status)
	}
	status, _ = doJSON(t, http.MethodDelete, ts.URL+"/api/v1/rules/"+created.Data.ID, nil)
	if status != http.StatusNotFound {
		t.Fatalf("second delete status=%d", status)
	}
}

func TestSessionSaveLoadDelete(t *testing.T) {
	ts, st, _ := newM2Server(t)
	for _, f := range flow.Generate(4) {
		st.Add(f)
	}
	before := st.Stats().Count

	status, data := doJSON(t, http.MethodPost, ts.URL+"/api/v1/sessions", map[string]any{"name": "存档 A"})
	if status != http.StatusOK {
		t.Fatalf("save status=%d body=%s", status, data)
	}
	var saved struct {
		Data persist.SavedSession `json:"data"`
	}
	if err := json.Unmarshal(data, &saved); err != nil || saved.Data.FlowCount != int64(before) {
		t.Fatalf("saved=%s err=%v", data, err)
	}

	status, data = doJSON(t, http.MethodGet, ts.URL+"/api/v1/sessions", nil)
	var list struct {
		Data []persist.SavedSession `json:"data"`
	}
	if err := json.Unmarshal(data, &list); err != nil || status != http.StatusOK || len(list.Data) != 1 {
		t.Fatalf("list status=%d data=%s err=%v", status, data, err)
	}

	if status, _ := doJSON(t, http.MethodDelete, ts.URL+"/api/v1/flows?confirm=true", nil); status != http.StatusOK {
		t.Fatalf("clear status=%d", status)
	}
	if st.Stats().Count != 0 {
		t.Fatal("flows not cleared")
	}

	status, data = doJSON(t, http.MethodPost, ts.URL+"/api/v1/sessions/"+saved.Data.ID+"/load", nil)
	if status != http.StatusOK {
		t.Fatalf("load status=%d body=%s", status, data)
	}
	var loaded struct {
		Data struct {
			Count int `json:"count"`
		} `json:"data"`
	}
	_ = json.Unmarshal(data, &loaded)
	if loaded.Data.Count != before || st.Stats().Count != before {
		t.Fatalf("loaded=%s stats=%+v", data, st.Stats())
	}

	if status, _ := doJSON(t, http.MethodDelete, ts.URL+"/api/v1/sessions/"+saved.Data.ID, nil); status != http.StatusOK {
		t.Fatalf("delete status=%d", status)
	}
	if status, _ := doJSON(t, http.MethodPost, ts.URL+"/api/v1/sessions/"+saved.Data.ID+"/load", nil); status != http.StatusNotFound {
		t.Fatalf("load missing status=%d", status)
	}
}

func TestFullBodyAPI(t *testing.T) {
	ts, st, blobs := newM2Server(t)
	full := strings.Repeat("0123456789", 1000)
	ref, err := blobs.Put([]byte(full))
	if err != nil {
		t.Fatal(err)
	}
	f := &flow.Flow{
		Host:       "body.example.com",
		Method:     "GET",
		Path:       "/full",
		StatusCode: 200,
		Mime:       "text/plain",
		State:      flow.StateCompleted,
		Mode:       flow.ModeProxy,
		Request:    &flow.Message{HTTPVersion: "HTTP/1.1", Headers: flow.Headers{}},
		Response: &flow.Message{
			HTTPVersion: "HTTP/1.1",
			Headers:     flow.Headers{{Name: "Content-Type", Value: "text/plain"}},
			Body:        &flow.Body{Ref: ref, Size: int64(len(full)), CapturedSize: 2048, Mime: "text/plain", Text: true, Preview: full[:2048]},
		},
		Tags:      []string{},
		StartedAt: time.Now(),
	}
	added := st.Add(f)

	resp, err := http.Get(ts.URL + "/api/v1/flows/" + added.ID + "/body?direction=response")
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(data) != full {
		t.Fatalf("body status=%d len=%d", resp.StatusCode, len(data))
	}
	if resp.Header.Get("X-Scanning-Body-Ref") != ref {
		t.Fatalf("body ref header = %q", resp.Header.Get("X-Scanning-Body-Ref"))
	}
}

func TestResumeAndBreakpoints(t *testing.T) {
	ts, _, _ := newM2Server(t)
	status, data := doJSON(t, http.MethodGet, ts.URL+"/api/v1/breakpoints", nil)
	if status != http.StatusOK || !strings.Contains(string(data), `"data":[]`) {
		t.Fatalf("breakpoints status=%d data=%s", status, data)
	}
	status, _ = doJSON(t, http.MethodPost, ts.URL+"/api/v1/flows/not-paused/resume", map[string]any{"action": "forward"})
	if status != http.StatusServiceUnavailable {
		// 测试服务器未装配代理引擎，应明确返回不可用。
		t.Fatalf("resume status=%d", status)
	}
}
