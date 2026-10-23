package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"scanning/internal/config"
	"scanning/internal/event"
	"scanning/internal/flow"
	"scanning/internal/launcher"
	"scanning/internal/store"
)

func TestAppsAPI(t *testing.T) {
	cfg := config.Default()
	session := flow.Session{ID: "session-apps", Name: "应用会话", Mode: flow.ModeProxy, CreatedAt: time.Now()}
	st := store.NewRing(10, session.ID)
	hub := event.NewHub(session.ID)
	t.Cleanup(hub.Close)
	manager := launcher.NewManager(t.TempDir())
	s := New(Options{
		Config:   cfg,
		Store:    st,
		Hub:      hub,
		Launcher: manager,
		Session:  session,
		DataDir:  t.TempDir(),
		Dev:      true,
	})
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()

	status, data := doJSON(t, http.MethodGet, ts.URL+"/api/v1/apps", nil)
	if status != http.StatusOK {
		t.Fatalf("apps status=%d body=%s", status, data)
	}
	var list struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(data, &list); err != nil || len(list.Data) != 0 {
		t.Fatalf("apps=%s err=%v", data, err)
	}

	status, data = doJSON(t, http.MethodGet, ts.URL+"/api/v1/apps/recent", nil)
	if status != http.StatusOK {
		t.Fatalf("recent status=%d body=%s", status, data)
	}

	status, _ = doJSON(t, http.MethodGet, ts.URL+"/api/v1/apps/missing", nil)
	if status != http.StatusNotFound {
		t.Fatalf("missing app status=%d", status)
	}

	status, data = doJSON(t, http.MethodPost, ts.URL+"/api/v1/apps/launch", map[string]any{"path": "Z:\\missing.exe"})
	if status != http.StatusConflict {
		t.Fatalf("launch without proxy status=%d body=%s", status, data)
	}
}
