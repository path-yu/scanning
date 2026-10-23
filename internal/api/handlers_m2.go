package api

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"time"

	"scanning/internal/flow"
	"scanning/internal/proxy"
	"scanning/internal/rules"
)

func (s *Server) handleListRules(w http.ResponseWriter, r *http.Request) {
	if s.rules == nil {
		writeError(w, r, http.StatusServiceUnavailable, "RULES_UNAVAILABLE", "规则存储未初始化", nil)
		return
	}
	writeData(w, r, s.rules.List(), nil)
}

func (s *Server) handleSaveRule(w http.ResponseWriter, r *http.Request) {
	if s.rules == nil {
		writeError(w, r, http.StatusServiceUnavailable, "RULES_UNAVAILABLE", "规则存储未初始化", nil)
		return
	}
	var rule rules.Rule
	if err := decodeJSON(w, r, &rule); err != nil {
		writeError(w, r, http.StatusBadRequest, "BAD_REQUEST", "请求体无效: "+err.Error(), nil)
		return
	}
	rule.ID = ""
	saved, err := s.rules.Save(rule)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "RULE_INVALID", err.Error(), nil)
		return
	}
	s.hub.Broadcast("rules.changed", s.rules.List())
	writeData(w, r, saved, nil)
}

func (s *Server) handleUpdateRule(w http.ResponseWriter, r *http.Request) {
	if s.rules == nil {
		writeError(w, r, http.StatusServiceUnavailable, "RULES_UNAVAILABLE", "规则存储未初始化", nil)
		return
	}
	id := r.PathValue("id")
	if id == "" {
		writeError(w, r, http.StatusBadRequest, "BAD_REQUEST", "缺少规则 ID", nil)
		return
	}
	var rule rules.Rule
	if err := decodeJSON(w, r, &rule); err != nil {
		writeError(w, r, http.StatusBadRequest, "BAD_REQUEST", "请求体无效: "+err.Error(), nil)
		return
	}
	rule.ID = id
	saved, err := s.rules.Save(rule)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "RULE_INVALID", err.Error(), nil)
		return
	}
	s.hub.Broadcast("rules.changed", s.rules.List())
	writeData(w, r, saved, nil)
}

func (s *Server) handleDeleteRule(w http.ResponseWriter, r *http.Request) {
	if s.rules == nil {
		writeError(w, r, http.StatusServiceUnavailable, "RULES_UNAVAILABLE", "规则存储未初始化", nil)
		return
	}
	id := r.PathValue("id")
	if !s.rules.Delete(id) {
		writeError(w, r, http.StatusNotFound, "RULE_NOT_FOUND", "规则不存在", map[string]any{"id": id})
		return
	}
	s.hub.Broadcast("rules.changed", s.rules.List())
	writeData(w, r, map[string]any{"id": id, "deleted": true}, nil)
}

func (s *Server) handleResumeFlow(w http.ResponseWriter, r *http.Request) {
	if s.proxy == nil {
		writeError(w, r, http.StatusServiceUnavailable, "PROXY_UNAVAILABLE", "代理引擎未初始化", nil)
		return
	}
	id := r.PathValue("id")
	var cmd proxy.ResumeCommand
	if err := decodeJSON(w, r, &cmd); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, r, http.StatusBadRequest, "BAD_REQUEST", "请求体无效: "+err.Error(), nil)
		return
	}
	if !s.proxy.Resume(id, cmd) {
		writeError(w, r, http.StatusConflict, "NOT_PAUSED", "该 Flow 当前不在断点等待中", map[string]any{"id": id})
		return
	}
	writeData(w, r, map[string]any{"id": id, "resumed": true, "action": cmd.Action}, nil)
}

func (s *Server) handleBreakpoints(w http.ResponseWriter, r *http.Request) {
	if s.proxy == nil {
		writeData(w, r, []flow.Summary{}, nil)
		return
	}
	ids := s.proxy.Paused()
	summaries := make([]flow.Summary, 0, len(ids))
	for _, id := range ids {
		if f, ok := s.store.Get(id); ok {
			summaries = append(summaries, f.Summary())
		}
	}
	writeData(w, r, summaries, nil)
}

type replayRequest struct {
	Method  string        `json:"method,omitempty"`
	URL     string        `json:"url,omitempty"`
	Headers []flow.Header `json:"headers,omitempty"`
	Body    *string       `json:"body,omitempty"`
}

func (s *Server) handleReplayFlow(w http.ResponseWriter, r *http.Request) {
	if s.proxy == nil {
		writeError(w, r, http.StatusServiceUnavailable, "PROXY_UNAVAILABLE", "代理引擎未初始化", nil)
		return
	}
	id := r.PathValue("id")
	src, ok := s.store.Get(id)
	if !ok {
		writeError(w, r, http.StatusNotFound, "FLOW_NOT_FOUND", "Flow 不存在或已被淘汰", map[string]any{"id": id})
		return
	}
	var req replayRequest
	if err := decodeJSON(w, r, &req); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, r, http.StatusBadRequest, "BAD_REQUEST", "请求体无效: "+err.Error(), nil)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	replayed, err := s.proxy.Replay(ctx, src, proxy.ReplayOverrides{
		Method:  req.Method,
		URL:     req.URL,
		Headers: req.Headers,
		Body:    req.Body,
	})
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "REPLAY_FAILED", err.Error(), nil)
		return
	}
	writeData(w, r, replayed, nil)
}

func (s *Server) handleSaveSession(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		writeError(w, r, http.StatusServiceUnavailable, "PERSISTENCE_UNAVAILABLE", "会话持久化未启用", nil)
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if err := decodeJSON(w, r, &req); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, r, http.StatusBadRequest, "BAD_REQUEST", "请求体无效: "+err.Error(), nil)
		return
	}
	session := s.sessionSnapshot()
	if req.Name != "" {
		session.Name = req.Name
	}
	now := time.Now()
	session.EndedAt = &now
	flows := s.store.All()
	saved, err := s.db.Save(r.Context(), session, flows)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "SESSION_SAVE_FAILED", err.Error(), nil)
		return
	}
	s.hub.Broadcast("session.saved", saved)
	writeData(w, r, saved, nil)
}

func (s *Server) handleLoadSession(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		writeError(w, r, http.StatusServiceUnavailable, "PERSISTENCE_UNAVAILABLE", "会话持久化未启用", nil)
		return
	}
	id := r.PathValue("id")
	loaded, items, err := s.db.Load(r.Context(), id)
	if errors.Is(err, os.ErrNotExist) {
		writeError(w, r, http.StatusNotFound, "SESSION_NOT_FOUND", "已保存的会话不存在", map[string]any{"id": id})
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "SESSION_LOAD_FAILED", err.Error(), nil)
		return
	}
	count := s.store.Restore(items)
	s.hub.Broadcast("session.loaded", map[string]any{"session": loaded, "count": count})
	writeData(w, r, map[string]any{"session": loaded, "count": count}, nil)
}

func (s *Server) handleDeleteSession(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		writeError(w, r, http.StatusServiceUnavailable, "PERSISTENCE_UNAVAILABLE", "会话持久化未启用", nil)
		return
	}
	id := r.PathValue("id")
	deleted, err := s.db.Delete(r.Context(), id)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "SESSION_DELETE_FAILED", err.Error(), nil)
		return
	}
	if !deleted {
		writeError(w, r, http.StatusNotFound, "SESSION_NOT_FOUND", "已保存的会话不存在", map[string]any{"id": id})
		return
	}
	s.hub.Broadcast("session.deleted", map[string]any{"id": id})
	writeData(w, r, map[string]any{"id": id, "deleted": true}, nil)
}
