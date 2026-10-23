package api

import (
	"net/http"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"unicode/utf8"

	"scanning/internal/blob"
	"scanning/internal/eapi"
	"scanning/internal/flow"
)

const (
	maxSearchQueryRunes = 200
	maxSearchBodyBytes  = 32 << 20
	maxSearchResults    = 2000
)

type flowSearchPayload struct {
	Query     string   `json:"query"`
	IDs       []string `json:"ids"`
	Count     int      `json:"count"`
	Scanned   int      `json:"scanned"`
	Truncated bool     `json:"truncated,omitempty"`
}

// handleSearchFlows 在 URL、头和完整正文中搜索关键字，返回命中的 Flow ID。
// 前端只持有 Summary，无法看到正文，因此关键字正文搜索由服务端完成。
func (s *Server) handleSearchFlows(w http.ResponseWriter, r *http.Request) {
	query := strings.Join(strings.Fields(r.URL.Query().Get("q")), " ")
	if query == "" {
		writeError(w, r, http.StatusBadRequest, "BAD_REQUEST", "搜索关键字不能为空", nil)
		return
	}
	if utf8.RuneCountInString(query) > maxSearchQueryRunes {
		writeError(w, r, http.StatusBadRequest, "BAD_REQUEST", "搜索关键字过长", nil)
		return
	}

	needle := strings.ToLower(query)
	scope := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("scope")))
	switch scope {
	case "", "all":
		scope = "all"
	case "url", "request", "response", "body":
	default:
		writeError(w, r, http.StatusBadRequest, "BAD_REQUEST", "scope 仅支持 url、request、response、body 或 all", nil)
		return
	}
	flows := s.store.All()
	matched := make([]bool, len(flows))
	workers := runtime.NumCPU()
	if workers > len(flows) {
		workers = len(flows)
	}
	if workers > 8 {
		workers = 8
	}
	if workers > 0 {
		var cursor atomic.Int64
		var wg sync.WaitGroup
		wg.Add(workers)
		for i := 0; i < workers; i++ {
			go func() {
				defer wg.Done()
				for {
					index := int(cursor.Add(1)) - 1
					if index >= len(flows) || r.Context().Err() != nil {
						return
					}
					if s.matchFlowKeyword(flows[index], needle, scope) {
						matched[index] = true
					}
				}
			}()
		}
		wg.Wait()
	}
	if r.Context().Err() != nil {
		return
	}
	ids := make([]string, 0, 16)
	truncated := false
	for index, ok := range matched {
		if !ok {
			continue
		}
		ids = append(ids, flows[index].ID)
		if len(ids) >= maxSearchResults {
			truncated = true
			break
		}
	}

	writeData(w, r, flowSearchPayload{
		Query:     query,
		IDs:       ids,
		Count:     len(ids),
		Scanned:   len(flows),
		Truncated: truncated,
	}, nil)
}

func (s *Server) matchFlowKeyword(f *flow.Flow, needle, scope string) bool {
	if f == nil {
		return false
	}
	if scope == "url" {
		for _, value := range []string{f.Host, f.Path, f.Method, f.URL()} {
			if containsFold(value, needle) {
				return true
			}
		}
		return false
	}
	switch scope {
	case "request":
		return s.matchMessageBody(f, f.Request, "request", needle)
	case "response":
		return s.matchMessageBody(f, f.Response, "response", needle)
	case "body":
		return s.matchMessageBody(f, f.Request, "request", needle) ||
			s.matchMessageBody(f, f.Response, "response", needle)
	}

	for _, value := range []string{f.Host, f.Path, f.Method, f.URL(), f.Note} {
		if containsFold(value, needle) {
			return true
		}
	}
	for _, tag := range f.Tags {
		if containsFold(tag, needle) {
			return true
		}
	}
	if s.matchMessageKeyword(f, f.Request, "request", needle, true) {
		return true
	}
	return s.matchMessageKeyword(f, f.Response, "response", needle, true)
}

func (s *Server) matchMessageKeyword(f *flow.Flow, message *flow.Message, direction, needle string, includeHeaders bool) bool {
	if message == nil {
		return false
	}
	if includeHeaders {
		for _, header := range message.Headers {
			if containsFold(header.Name, needle) || containsFold(header.Value, needle) {
				return true
			}
		}
	}
	return s.matchMessageBody(f, message, direction, needle)
}

func (s *Server) matchMessageBody(f *flow.Flow, message *flow.Message, direction, needle string) bool {
	if message == nil {
		return false
	}
	body := message.Body
	if body == nil {
		return false
	}
	// 预览已经是解码/解密后的文本，先做一次低成本匹配。
	if containsFold(body.Preview, needle) {
		return true
	}
	if s.blobs == nil || body.Ref == "" {
		return false
	}
	data, err := s.blobs.GetLimited(body.Ref, maxSearchBodyBytes)
	if err != nil || len(data) == 0 {
		return false
	}
	if eapi.IsEAPI(f.Host, f.Path) {
		var plain []byte
		var ok bool
		if direction == "request" {
			plain, ok = eapi.DecryptRequest(data)
		} else {
			plain, ok = eapi.DecryptResponse(data)
		}
		if ok {
			return containsFold(string(plain), needle)
		}
		return false
	}
	if body.Encoding != "" {
		if decoded, ok := blob.Decode(data, body.Encoding); ok {
			data = decoded
		}
	}
	return containsFold(string(data), needle)
}

func containsFold(value, needle string) bool {
	return needle != "" && strings.Contains(strings.ToLower(value), needle)
}
