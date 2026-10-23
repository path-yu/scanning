package rules

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/oklog/ulid/v2"

	"scanning/internal/flow"
)

const (
	PhaseRequest  = "request"
	PhaseResponse = "response"
)

const (
	ActionMock            = "mock"
	ActionBlock           = "block"
	ActionDelay           = "delay"
	ActionMapRemote       = "map_remote"
	ActionRewriteRequest  = "rewrite_request"
	ActionRewriteResponse = "rewrite_response"
	ActionPause           = "pause"
)

var actionTypes = map[string]struct{}{
	ActionMock:            {},
	ActionBlock:           {},
	ActionDelay:           {},
	ActionMapRemote:       {},
	ActionRewriteRequest:  {},
	ActionRewriteResponse: {},
	ActionPause:           {},
}

type Match struct {
	Methods      []string `json:"methods,omitempty"`
	Host         string   `json:"host,omitempty"`
	Path         string   `json:"path,omitempty"`
	Status       string   `json:"status,omitempty"`
	Mime         string   `json:"mime,omitempty"`
	HeaderName   string   `json:"headerName,omitempty"`
	HeaderValue  string   `json:"headerValue,omitempty"`
	BodyContains string   `json:"bodyContains,omitempty"`
}

type Action struct {
	Type          string        `json:"type"`
	Status        int           `json:"status,omitempty"`
	Headers       []flow.Header `json:"headers,omitempty"`
	RemoveHeaders []string      `json:"removeHeaders,omitempty"`
	Body          *string       `json:"body,omitempty"`
	DelayMs       int           `json:"delayMs,omitempty"`
	Remote        string        `json:"remote,omitempty"`
	Method        string        `json:"method,omitempty"`
	Path          string        `json:"path,omitempty"`
}

type Rule struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Enabled   bool      `json:"enabled"`
	Priority  int       `json:"priority"`
	Phase     string    `json:"phase"`
	Stop      bool      `json:"stop"`
	Match     Match     `json:"match"`
	Actions   []Action  `json:"actions"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// Meta 是规则匹配所需的报文快照。
type Meta struct {
	Method  string
	Host    string
	Path    string
	Status  int
	Mime    string
	Headers flow.Headers
	Body    []byte
}

type Store struct {
	mu    sync.RWMutex
	path  string
	items []Rule
}

func NewStore(path string) (*Store, error) {
	s := &Store{path: path}
	if path == "" {
		return s, nil
	}
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		var payload struct {
			Version int    `json:"version"`
			Rules   []Rule `json:"rules"`
		}
		if err := json.Unmarshal(data, &payload); err != nil {
			return nil, fmt.Errorf("解析规则文件 %s: %w", path, err)
		}
		s.items = payload.Rules
		sortRules(s.items)
	case errors.Is(err, os.ErrNotExist):
	default:
		return nil, fmt.Errorf("读取规则文件 %s: %w", path, err)
	}
	return s, nil
}

func (s *Store) List() []Rule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Rule, len(s.items))
	for i, item := range s.items {
		out[i] = cloneRule(item)
	}
	return out
}

func (s *Store) Get(id string) (Rule, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, item := range s.items {
		if item.ID == id {
			return cloneRule(item), true
		}
	}
	return Rule{}, false
}

func (s *Store) Save(input Rule) (Rule, error) {
	if err := Validate(input); err != nil {
		return Rule{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	rule := cloneRule(input)
	rule.Name = strings.TrimSpace(rule.Name)
	rule.Phase = strings.ToLower(strings.TrimSpace(rule.Phase))

	idx := -1
	for i := range s.items {
		if s.items[i].ID == rule.ID && rule.ID != "" {
			idx = i
			break
		}
	}
	if idx >= 0 {
		rule.CreatedAt = s.items[idx].CreatedAt
		rule.UpdatedAt = now
		s.items[idx] = rule
	} else {
		if rule.ID == "" {
			rule.ID = ulid.Make().String()
		}
		rule.CreatedAt = now
		rule.UpdatedAt = now
		s.items = append(s.items, rule)
	}
	sortRules(s.items)
	if err := s.persistLocked(); err != nil {
		return Rule{}, err
	}
	return cloneRule(rule), nil
}

func (s *Store) Delete(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.items {
		if s.items[i].ID == id {
			s.items = append(s.items[:i], s.items[i+1:]...)
			_ = s.persistLocked()
			return true
		}
	}
	return false
}

// Match 返回按优先级排序的、与 phase 和 meta 匹配的启用规则。
func (s *Store) Match(phase string, meta Meta) []Rule {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]Rule, 0, 4)
	for _, item := range s.items {
		if !item.Enabled || item.Phase != phase {
			continue
		}
		if item.matches(phase, meta) {
			out = append(out, cloneRule(item))
		}
	}
	return out
}

func (s *Store) persistLocked() error {
	if s.path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return fmt.Errorf("创建规则目录: %w", err)
	}
	payload := struct {
		Version int    `json:"version"`
		Rules   []Rule `json:"rules"`
	}{Version: 1, Rules: s.items}
	if payload.Rules == nil {
		payload.Rules = []Rule{}
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("写入规则文件: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return fmt.Errorf("替换规则文件: %w", err)
	}
	return nil
}

func (r Rule) matches(phase string, meta Meta) bool {
	if len(r.Match.Methods) > 0 && !matchList(r.Match.Methods, meta.Method, true) {
		return false
	}
	if r.Match.Host != "" && !wildcard(r.Match.Host, meta.Host, true) {
		return false
	}
	if r.Match.Path != "" && !wildcard(r.Match.Path, meta.Path, false) {
		return false
	}
	if phase == PhaseResponse {
		if r.Match.Status != "" && !matchStatus(r.Match.Status, meta.Status) {
			return false
		}
		if r.Match.Mime != "" && !wildcard(r.Match.Mime, meta.Mime, true) {
			return false
		}
		return true
	}
	if r.Match.HeaderName != "" {
		value, ok := findHeader(meta.Headers, r.Match.HeaderName)
		if !ok {
			return false
		}
		if r.Match.HeaderValue != "" && !strings.Contains(strings.ToLower(value), strings.ToLower(r.Match.HeaderValue)) {
			return false
		}
	}
	if r.Match.BodyContains != "" {
		if len(meta.Body) == 0 || !strings.Contains(string(meta.Body), r.Match.BodyContains) {
			return false
		}
	}
	return true
}

func Validate(rule Rule) error {
	if strings.TrimSpace(rule.Name) == "" {
		return errors.New("规则名称不能为空")
	}
	if len(rule.Name) > 120 {
		return errors.New("规则名称最多 120 字符")
	}
	if rule.Phase != PhaseRequest && rule.Phase != PhaseResponse {
		return errors.New("phase 必须是 request 或 response")
	}
	if len(rule.Actions) == 0 {
		return errors.New("规则至少需要一个动作")
	}
	if len(rule.Actions) > 8 {
		return errors.New("规则最多 8 个动作")
	}
	for i, action := range rule.Actions {
		kind := strings.ToLower(strings.TrimSpace(action.Type))
		if _, ok := actionTypes[kind]; !ok {
			return fmt.Errorf("动作 %d 类型无效: %s", i+1, action.Type)
		}
		if rule.Phase == PhaseResponse {
			switch kind {
			case ActionMapRemote, ActionRewriteRequest:
				return fmt.Errorf("动作 %d（%s）只能在请求阶段使用", i+1, kind)
			}
		}
		if rule.Phase == PhaseRequest && kind == ActionRewriteResponse {
			return fmt.Errorf("动作 %d（%s）只能在响应阶段使用", i+1, kind)
		}
		if action.Status != 0 && (action.Status < 100 || action.Status > 599) {
			return fmt.Errorf("动作 %d 状态码需在 100-599 之间", i+1)
		}
		if action.DelayMs < 0 || action.DelayMs > 60000 {
			return fmt.Errorf("动作 %d 延迟需在 0-60000 毫秒之间", i+1)
		}
		for _, header := range action.Headers {
			if strings.TrimSpace(header.Name) == "" {
				return fmt.Errorf("动作 %d 的 Header 名称不能为空", i+1)
			}
		}
	}
	if rule.Match.Status != "" {
		for _, token := range strings.Split(rule.Match.Status, ",") {
			token = strings.TrimSpace(token)
			if token == "" || token == "*" {
				continue
			}
			if len(token) == 3 && strings.HasSuffix(strings.ToLower(token), "xx") {
				if token[0] < '1' || token[0] > '5' {
					return fmt.Errorf("状态匹配 %q 无效", token)
				}
				continue
			}
			if n, err := strconv.Atoi(token); err != nil || n < 100 || n > 599 {
				return fmt.Errorf("状态匹配 %q 无效", token)
			}
		}
	}
	return nil
}

func cloneRule(rule Rule) Rule {
	out := rule
	out.Match.Methods = append([]string(nil), rule.Match.Methods...)
	if rule.Actions != nil {
		out.Actions = make([]Action, len(rule.Actions))
		for i, action := range rule.Actions {
			out.Actions[i] = action
			if action.Headers != nil {
				out.Actions[i].Headers = make([]flow.Header, len(action.Headers))
				copy(out.Actions[i].Headers, action.Headers)
			}
			out.Actions[i].RemoveHeaders = append([]string(nil), action.RemoveHeaders...)
			if action.Body != nil {
				body := *action.Body
				out.Actions[i].Body = &body
			}
		}
	}
	return out
}

func sortRules(items []Rule) {
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].Priority == items[j].Priority {
			if items[i].CreatedAt.Equal(items[j].CreatedAt) {
				return items[i].ID < items[j].ID
			}
			return items[i].CreatedAt.Before(items[j].CreatedAt)
		}
		return items[i].Priority < items[j].Priority
	})
}

func matchList(patterns []string, value string, fold bool) bool {
	for _, pattern := range patterns {
		if wildcard(pattern, value, fold) {
			return true
		}
	}
	return false
}

func matchStatus(pattern string, status int) bool {
	for _, token := range strings.Split(pattern, ",") {
		token = strings.TrimSpace(strings.ToLower(token))
		switch {
		case token == "" || token == "*":
			if token == "*" {
				return true
			}
		case strings.HasSuffix(token, "xx"):
			if len(token) != 3 {
				continue
			}
			if status/100 == int(token[0]-'0') {
				return true
			}
		default:
			if n, err := strconv.Atoi(token); err == nil && n == status {
				return true
			}
		}
	}
	return false
}

func findHeader(headers flow.Headers, name string) (string, bool) {
	for _, header := range headers {
		if strings.EqualFold(header.Name, name) {
			return header.Value, true
		}
	}
	return "", false
}

// wildcard 支持 * 与 ? 通配符；fold 用于域名与 MIME 等大小写不敏感场景。
func wildcard(pattern, value string, fold bool) bool {
	if fold {
		pattern = strings.ToLower(pattern)
		value = strings.ToLower(value)
	}
	pattern = strings.TrimSpace(pattern)
	if pattern == "" || pattern == "*" {
		return true
	}
	pi, vi := 0, 0
	star := -1
	match := 0
	for vi < len(value) {
		if pi < len(pattern) && (pattern[pi] == '?' || pattern[pi] == value[vi]) {
			pi++
			vi++
			continue
		}
		if pi < len(pattern) && pattern[pi] == '*' {
			star = pi
			match = vi
			pi++
			continue
		}
		if star >= 0 {
			pi = star + 1
			match++
			vi = match
			continue
		}
		return false
	}
	for pi < len(pattern) && pattern[pi] == '*' {
		pi++
	}
	return pi == len(pattern)
}
