package api

import (
	"net/http"
	"strings"
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
	flows := s.store.All()
	ids := make([]string, 0, 16)
	truncated := false
	for _, f := range flows {
		if r.Context().Err() != nil {
			return
		}
		if s.matchFlowKeyword(f, needle) {
			ids = append(ids, f.ID)
			if len(ids) >= maxSearchResults {
				truncated = true
				break
			}
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

func (s *Server) matchFlowKeyword(f *flow.Flow, needle string) bool {
	if f == nil {
		return false
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
	if s.matchMessageKeyword(f, f.Request, "request", needle) {
		return true
	}
	return s.matchMessageKeyword(f, f.Response, "response", needle)
}

func (s *Server) matchMessageKeyword(f *flow.Flow, message *flow.Message, direction, needle string) bool {
	if message == nil {
		return false
	}
	for _, header := range message.Headers {
		if containsFold(header.Name, needle) || containsFold(header.Value, needle) {
			return true
		}
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
