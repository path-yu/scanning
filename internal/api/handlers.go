package api

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math"
	"net/http"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"scanning/internal/blob"
	"scanning/internal/capture"
	"scanning/internal/eapi"
	"scanning/internal/flow"
	"scanning/internal/proxy"
	"scanning/web"
)

type statsPayload struct {
	Flows       int     `json:"flows"`
	Capacity    int     `json:"capacity"`
	Bytes       int64   `json:"bytes"`
	Evicted     int64   `json:"evicted"`
	WSClients   int     `json:"wsClients"`
	MemoryBytes uint64  `json:"memoryBytes"`
	UptimeSec   int64   `json:"uptimeSec"`
	QPS         float64 `json:"qps"`
	SessionID   string  `json:"sessionId"`
}

type domainStat struct {
	Host    string         `json:"host"`
	Count   int            `json:"count"`
	Bytes   int64          `json:"bytes"`
	Errors  int            `json:"errors"`
	Methods map[string]int `json:"methods"`
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, envelope{Data: map[string]any{
		"status":  "ok",
		"version": versionString(),
		"mode":    "m5",
	}})
}

func (s *Server) handleSystemInfo(w http.ResponseWriter, r *http.Request) {
	stats := s.store.Stats()
	session := s.sessionSnapshot()
	proxyStatus := proxy.Status{Addr: s.opts.Config.Proxy.Addr, MITM: s.opts.Config.Proxy.MITM}
	if s.proxy != nil {
		proxyStatus = s.proxy.Status()
	}
	var captureStatus capture.CaptureStatus
	if s.capture != nil {
		captureStatus = s.capture.Status()
	}
	writeData(w, r, map[string]any{
		"version":  versionString(),
		"platform": platformString(),
		"dataDir":  s.opts.DataDir,
		"dev":      s.opts.Dev,
		"headless": s.opts.Headless,
		"session":  session,
		"proxy":    proxyStatus,
		"capture":  captureStatus,
		"capabilities": map[string]bool{
			"mitm":        s.certs != nil && s.proxy != nil,
			"pcap":        s.capture != nil,
			"pcapLive":    captureStatus.Available,
			"pcapImport":  s.capture != nil,
			"pcapMirror":  s.capture != nil,
			"persistence": s.db != nil,
			"rules":       s.rules != nil,
			"breakpoints": s.proxy != nil,
			"replay":      s.proxy != nil,
			"har":         true,
			"hook":        s.hook != nil,
		},
		"demo": map[string]any{
			"enabled": s.opts.Config.Demo.Enabled,
			"seed":    s.opts.Config.Demo.Seed,
		},
		"ui": map[string]any{
			"embedded": !web.Dev,
		},
		"store": stats,
	}, nil)
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	writeData(w, r, s.StatsData(), nil)
}

// StatsData 同时用于 REST 与 WebSocket stats 事件，保证 UI 看到一致的快照。
func (s *Server) StatsData() statsPayload {
	st := s.store.Stats()
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	qps := math.Round(s.calcQPS()*10) / 10

	return statsPayload{
		Flows:       st.Count,
		Capacity:    st.Capacity,
		Bytes:       st.Bytes,
		Evicted:     st.Evicted,
		WSClients:   s.hub.ClientCount(),
		MemoryBytes: mem.HeapAlloc,
		UptimeSec:   s.uptimeSeconds(),
		QPS:         qps,
		SessionID:   s.opts.Session.ID,
	}
}

func (s *Server) handleSessions(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		writeData(w, r, []any{}, nil)
		return
	}
	items, err := s.db.List(r.Context())
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "SESSION_LIST_FAILED", err.Error(), nil)
		return
	}
	writeData(w, r, items, map[string]any{"current": s.sessionSnapshot()})
}

func (s *Server) handleListFlows(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if sid := q.Get("sessionId"); sid != "" && sid != s.opts.Session.ID {
		writeError(w, r, http.StatusNotFound, "SESSION_NOT_FOUND", "会话不存在", map[string]any{"sessionId": sid})
		return
	}

	pred, err := flow.CompileFilter(q.Get("filter"))
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "BAD_REQUEST", err.Error(), nil)
		return
	}

	limit := 100
	if raw := q.Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n <= 0 {
			writeError(w, r, http.StatusBadRequest, "BAD_REQUEST", "limit 无效", nil)
			return
		}
		limit = n
	}

	var cursor int64
	if raw := q.Get("cursor"); raw != "" {
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || n < 0 {
			writeError(w, r, http.StatusBadRequest, "BAD_REQUEST", "cursor 无效", nil)
			return
		}
		cursor = n
	}
	if raw := q.Get("sinceSeq"); raw != "" {
		n, err := strconv.ParseInt(raw, 10, 64)
		if err == nil && n > 0 {
			cursor = n
		}
	}

	desc := q.Get("order") != "asc"
	items, hasMore, total := s.store.List(pred, cursor, limit, desc)

	summaries := make([]flow.Summary, 0, len(items))
	for _, item := range items {
		summaries = append(summaries, item.Summary())
	}

	nextCursor := ""
	if len(summaries) > 0 {
		nextCursor = strconv.FormatInt(summaries[len(summaries)-1].Seq, 10)
	}
	writeData(w, r, summaries, map[string]any{
		"nextCursor": nextCursor,
		"hasMore":    hasMore,
		"total":      total,
		"limit":      limit,
		"order":      map[bool]string{true: "desc", false: "asc"}[desc],
	})
}

func (s *Server) handleGetFlow(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, r, http.StatusBadRequest, "BAD_REQUEST", "缺少 Flow ID", nil)
		return
	}
	f, ok := s.store.Get(id)
	if !ok {
		writeError(w, r, http.StatusNotFound, "FLOW_NOT_FOUND", "Flow 不存在或已被淘汰", map[string]any{"id": id})
		return
	}
	writeData(w, r, f, nil)
}

func (s *Server) handlePatchFlow(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, r, http.StatusBadRequest, "BAD_REQUEST", "缺少 Flow ID", nil)
		return
	}

	var patch flow.Patch
	if err := decodeJSON(w, r, &patch); err != nil {
		writeError(w, r, http.StatusBadRequest, "BAD_REQUEST", "请求体无效: "+err.Error(), nil)
		return
	}
	if patch.Tags != nil {
		if len(*patch.Tags) > 32 {
			writeError(w, r, http.StatusBadRequest, "BAD_REQUEST", "标签最多 32 个", nil)
			return
		}
		for _, tag := range *patch.Tags {
			if len(tag) > 64 {
				writeError(w, r, http.StatusBadRequest, "BAD_REQUEST", "单个标签最多 64 字符", nil)
				return
			}
		}
	}

	updated, ok := s.store.Patch(id, patch)
	if !ok {
		writeError(w, r, http.StatusNotFound, "FLOW_NOT_FOUND", "Flow 不存在或已被淘汰", map[string]any{"id": id})
		return
	}
	s.hub.Broadcast("flow.updated", updated.Summary())
	writeData(w, r, updated, nil)
}

func (s *Server) handleFlowBody(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	f, ok := s.store.Get(id)
	if !ok {
		writeError(w, r, http.StatusNotFound, "FLOW_NOT_FOUND", "Flow 不存在或已被淘汰", map[string]any{"id": id})
		return
	}

	direction := r.URL.Query().Get("direction")
	if direction == "" {
		direction = "response"
	}
	var body *flow.Body
	switch direction {
	case "request":
		if f.Request != nil {
			body = f.Request.Body
		}
	case "response":
		if f.Response != nil {
			body = f.Response.Body
		}
	default:
		writeError(w, r, http.StatusBadRequest, "BAD_REQUEST", "direction 必须是 request 或 response", nil)
		return
	}
	if body == nil {
		writeError(w, r, http.StatusNotFound, "BODY_NOT_READY", "正文不存在", nil)
		return
	}

	mime := body.Mime
	if mime == "" {
		mime = "text/plain; charset=utf-8"
	}
	w.Header().Set("Content-Type", mime)
	w.Header().Set("X-Scanning-Body-Size", strconv.FormatInt(body.Size, 10))
	w.Header().Set("X-Scanning-Captured-Size", strconv.FormatInt(body.CapturedSize, 10))
	w.Header().Set("X-Scanning-Truncated", strconv.FormatBool(body.Truncated))
	if body.Encoding != "" {
		w.Header().Set("X-Scanning-Encoding", body.Encoding)
	}
	if body.Ref != "" {
		w.Header().Set("X-Scanning-Body-Ref", body.Ref)
	}

	raw := r.URL.Query().Get("raw") == "1"
	var data []byte
	if s.blobs != nil && body.Ref != "" {
		if stored, err := s.blobs.Get(body.Ref); err == nil {
			data = stored
			if !raw {
				if decoded, ok := blob.Decode(stored, body.Encoding); ok {
					data = decoded
				} else if body.Encoding != "" {
					// 不支持的编码（如 br）原样返回。
					w.Header().Set("X-Scanning-Raw", "1")
				}
			} else {
				w.Header().Set("X-Scanning-Raw", "1")
			}
		}
	}
	if data == nil {
		// 兼容早期仅保存预览的 Flow。
		data = []byte(body.Preview)
	}
	decodedEAPI := false
	if !raw && eapi.IsEAPI(f.Host, f.Path) {
		var plain []byte
		var ok bool
		if direction == "request" {
			plain, ok = eapi.DecryptRequest(data)
		} else {
			plain, ok = eapi.DecryptResponse(data)
		}
		if ok {
			data = plain
			decodedEAPI = true
			mime = "application/json; charset=utf-8"
			w.Header().Set("Content-Type", mime)
			w.Header().Set("X-Scanning-Decrypted", "eapi")
		}
	}
	if !raw && !decodedEAPI && eapi.IsEAPI(f.Host, f.Path) && r.URL.Query().Get("download") == "1" {
		// 明确告知解密失败，避免把占位文本当作 JSON 下载。
		writeError(w, r, http.StatusUnprocessableEntity, "EAPI_DECRYPT_FAILED",
			"EAPI 解密失败：正文可能被截断或不是有效密文，可尝试下载原始正文", nil)
		return
	}
	if !raw && !decodedEAPI && (!body.Text || blob.LooksBinary(data)) {
		// Content-Type 可能被服务端声明为 text/plain，但正文实际是加密/二进制。
		// 默认不把大块二进制返回给浏览器，避免前端把它当文本渲染导致卡顿。
		w.Header().Set("X-Scanning-Binary", "1")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		data = []byte("二进制/加密内容，大小 " + strconv.FormatInt(body.Size, 10) + " 字节；使用 raw=1 获取原始正文。")
	}
	if r.URL.Query().Get("download") == "1" {
		ext := ".bin"
		if !raw {
			lower := strings.ToLower(mime)
			switch {
			case decodedEAPI, strings.Contains(lower, "json"):
				ext = ".json"
			case strings.Contains(lower, "html"):
				ext = ".html"
			case strings.Contains(lower, "xml"):
				ext = ".xml"
			case strings.Contains(lower, "javascript"):
				ext = ".js"
			case strings.Contains(lower, "x-www-form-urlencoded"):
				ext = ".txt"
			case strings.HasPrefix(lower, "text/"):
				ext = ".txt"
			}
		}
		name := "flow-" + f.ID + "-" + direction + ext
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (s *Server) handleDeleteFlows(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("confirm") != "true" {
		writeError(w, r, http.StatusBadRequest, "BAD_REQUEST", "批量删除需要 confirm=true", nil)
		return
	}

	hasIDs := false
	var ids []string
	if raw := strings.TrimSpace(r.URL.Query().Get("ids")); raw != "" {
		hasIDs = true
		for _, part := range strings.Split(raw, ",") {
			if id := strings.TrimSpace(part); id != "" {
				ids = append(ids, id)
			}
		}
	}
	var req struct {
		IDs []string `json:"ids"`
	}
	if err := decodeJSON(w, r, &req); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, r, http.StatusBadRequest, "BAD_REQUEST", "请求体无效: "+err.Error(), nil)
		return
	}
	if req.IDs != nil {
		hasIDs = true
		ids = append(ids, req.IDs...)
	}
	if len(ids) > 5000 {
		writeError(w, r, http.StatusBadRequest, "BAD_REQUEST", "一次最多删除 5000 条请求", nil)
		return
	}

	if hasIDs {
		count := s.store.Remove(ids)
		s.hub.Broadcast("flows.deleted", map[string]any{"ids": ids, "count": count})
		writeData(w, r, map[string]any{"count": count}, nil)
		return
	}

	count := s.store.Clear()
	s.hub.Broadcast("flows.cleared", map[string]any{"count": count})
	writeData(w, r, map[string]any{"count": count}, nil)
}

func (s *Server) handleDomains(w http.ResponseWriter, r *http.Request) {
	all := s.store.All()
	byHost := make(map[string]*domainStat)
	for _, f := range all {
		item := byHost[f.Host]
		if item == nil {
			item = &domainStat{Host: f.Host, Methods: map[string]int{}}
			byHost[f.Host] = item
		}
		item.Count++
		item.Bytes += f.ReqSize + f.RespSize
		item.Methods[f.Method]++
		if f.StatusCode >= 400 {
			item.Errors++
		}
	}

	out := make([]domainStat, 0, len(byHost))
	for _, item := range byHost {
		out = append(out, *item)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count == out[j].Count {
			return out[i].Host < out[j].Host
		}
		return out[i].Count > out[j].Count
	})
	writeData(w, r, out, nil)
}

func (s *Server) handleDemoFlows(w http.ResponseWriter, r *http.Request) {
	if !s.opts.Config.Demo.Enabled {
		writeError(w, r, http.StatusNotFound, "DEMO_DISABLED", "当前配置未启用演示数据", nil)
		return
	}

	var req struct {
		Count int `json:"count"`
	}
	if err := decodeJSON(w, r, &req); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, r, http.StatusBadRequest, "BAD_REQUEST", "请求体无效: "+err.Error(), nil)
		return
	}
	if req.Count <= 0 {
		req.Count = 10
	}
	if req.Count > 200 {
		req.Count = 200
	}

	generated := flow.Generate(req.Count)
	for _, f := range generated {
		added := s.store.Add(f)
		s.hub.Broadcast("flow.created", added.Summary())
	}
	slog.Info("生成演示流量", "count", len(generated))
	writeData(w, r, map[string]any{"count": len(generated)}, nil)
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	s.hub.Handle(w, r)
}

func (s *Server) sessionSnapshot() flow.Session {
	st := s.store.Stats()
	session := s.opts.Session
	session.FlowCount = int64(st.Count)
	session.ByteCount = st.Bytes
	return session
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	dec := json.NewDecoder(r.Body)
	return dec.Decode(dst)
}
