package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"scanning/internal/capture"
)

func (s *Server) handleCaptureStatus(w http.ResponseWriter, r *http.Request) {
	if s.capture == nil {
		writeError(w, r, http.StatusServiceUnavailable, "CAPTURE_UNAVAILABLE", "采集引擎未初始化", nil)
		return
	}
	writeData(w, r, s.capture.Status(), nil)
}

func (s *Server) handleInterfaces(w http.ResponseWriter, r *http.Request) {
	if s.capture == nil {
		writeError(w, r, http.StatusServiceUnavailable, "CAPTURE_UNAVAILABLE", "采集引擎未初始化", nil)
		return
	}
	items, err := s.capture.Interfaces()
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "INTERFACES_FAILED", err.Error(), nil)
		return
	}
	writeData(w, r, items, nil)
}

func (s *Server) handleCaptureStart(w http.ResponseWriter, r *http.Request) {
	if s.capture == nil {
		writeError(w, r, http.StatusServiceUnavailable, "CAPTURE_UNAVAILABLE", "采集引擎未初始化", nil)
		return
	}
	var req struct {
		Interface string `json:"interface"`
		BPF       string `json:"bpf"`
		Promisc   bool   `json:"promisc"`
	}
	if err := decodeJSON(w, r, &req); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, r, http.StatusBadRequest, "BAD_REQUEST", "请求体无效: "+err.Error(), nil)
		return
	}
	if req.BPF == "" {
		req.BPF = s.opts.Config.Capture.BPF
	}
	if err := s.capture.Start(req.Interface, req.BPF, req.Promisc); err != nil {
		writeError(w, r, http.StatusBadRequest, "CAPTURE_START_FAILED", err.Error(), nil)
		return
	}
	status := s.capture.Status()
	s.hub.Broadcast("capture.status", status)
	writeData(w, r, status, nil)
}

func (s *Server) handleCaptureStop(w http.ResponseWriter, r *http.Request) {
	if s.capture == nil {
		writeError(w, r, http.StatusServiceUnavailable, "CAPTURE_UNAVAILABLE", "采集引擎未初始化", nil)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 6*time.Second)
	defer cancel()
	if err := s.capture.Stop(ctx); err != nil {
		writeError(w, r, http.StatusInternalServerError, "CAPTURE_STOP_FAILED", err.Error(), nil)
		return
	}
	status := s.capture.Status()
	s.hub.Broadcast("capture.status", status)
	writeData(w, r, status, nil)
}

func (s *Server) handleCaptureMirror(w http.ResponseWriter, r *http.Request) {
	if s.capture == nil {
		writeError(w, r, http.StatusServiceUnavailable, "CAPTURE_UNAVAILABLE", "采集引擎未初始化", nil)
		return
	}
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := decodeJSON(w, r, &req); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, r, http.StatusBadRequest, "BAD_REQUEST", "请求体无效: "+err.Error(), nil)
		return
	}
	s.capture.SetMirror(req.Enabled)
	status := s.capture.Status()
	s.hub.Broadcast("capture.status", status)
	writeData(w, r, status, nil)
}

func (s *Server) handleCaptureImport(w http.ResponseWriter, r *http.Request) {
	if s.capture == nil {
		writeError(w, r, http.StatusServiceUnavailable, "CAPTURE_UNAVAILABLE", "采集引擎未初始化", nil)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 256<<20)
	result, err := s.capture.Import(r.Body, r.ContentLength)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "CAPTURE_IMPORT_FAILED", err.Error(), map[string]any{"partial": result})
		return
	}
	s.hub.Broadcast("capture.status", s.capture.Status())
	writeData(w, r, result, nil)
}

func (s *Server) handleListPackets(w http.ResponseWriter, r *http.Request) {
	if s.capture == nil {
		writeError(w, r, http.StatusServiceUnavailable, "CAPTURE_UNAVAILABLE", "采集引擎未初始化", nil)
		return
	}
	q := r.URL.Query()
	if sid := q.Get("sessionId"); sid != "" && sid != s.opts.Session.ID {
		writeError(w, r, http.StatusNotFound, "SESSION_NOT_FOUND", "会话不存在", map[string]any{"sessionId": sid})
		return
	}
	limit := 200
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
	desc := q.Get("order") != "asc"
	protocol := strings.ToUpper(strings.TrimSpace(q.Get("protocol")))
	search := strings.ToLower(strings.TrimSpace(q.Get("q")))

	match := func(p *capture.Packet) bool {
		if protocol != "" && protocol != "ALL" {
			switch protocol {
			case "DNS":
				if p.DNS == nil {
					return false
				}
			case "TLS":
				if p.TLS == nil {
					return false
				}
			default:
				if p.Protocol != protocol {
					return false
				}
			}
		}
		if search != "" {
			haystack := strings.ToLower(strings.Join([]string{
				p.SrcIP, p.DstIP, strconv.Itoa(p.SrcPort), strconv.Itoa(p.DstPort),
				p.Protocol, p.Summary, p.Host,
			}, " "))
			if !strings.Contains(haystack, search) {
				return false
			}
		}
		return true
	}

	items, hasMore, total := s.capture.Packets().List(cursor, limit, desc, match)
	nextCursor := int64(0)
	if len(items) > 0 {
		nextCursor = items[len(items)-1].No
	}
	writeData(w, r, items, map[string]any{
		"nextCursor": strconv.FormatInt(nextCursor, 10),
		"hasMore":    hasMore,
		"total":      total,
		"limit":      limit,
		"order":      map[bool]string{true: "desc", false: "asc"}[desc],
	})
}

func (s *Server) handleGetPacket(w http.ResponseWriter, r *http.Request) {
	if s.capture == nil {
		writeError(w, r, http.StatusServiceUnavailable, "CAPTURE_UNAVAILABLE", "采集引擎未初始化", nil)
		return
	}
	id := r.PathValue("id")
	packet, ok := s.capture.Packets().Get(id)
	if !ok {
		writeError(w, r, http.StatusNotFound, "PACKET_NOT_FOUND", "报文不存在或已被淘汰", map[string]any{"id": id})
		return
	}
	writeData(w, r, packet, nil)
}

func (s *Server) handleClearPackets(w http.ResponseWriter, r *http.Request) {
	if s.capture == nil {
		writeError(w, r, http.StatusServiceUnavailable, "CAPTURE_UNAVAILABLE", "采集引擎未初始化", nil)
		return
	}
	if r.URL.Query().Get("confirm") != "true" {
		writeError(w, r, http.StatusBadRequest, "BAD_REQUEST", "清空报文需要 confirm=true", nil)
		return
	}
	count := s.capture.ClearPackets()
	s.hub.Broadcast("packets.cleared", map[string]any{"count": count})
	s.hub.Broadcast("capture.status", s.capture.Status())
	writeData(w, r, map[string]any{"count": count}, nil)
}

func (s *Server) handleDNS(w http.ResponseWriter, r *http.Request) {
	if s.capture == nil {
		writeError(w, r, http.StatusServiceUnavailable, "CAPTURE_UNAVAILABLE", "采集引擎未初始化", nil)
		return
	}
	limit := 200
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			limit = n
		}
	}
	writeData(w, r, s.capture.DNS().Entries(limit), nil)
}

func (s *Server) handleExportPCAP(w http.ResponseWriter, r *http.Request) {
	if s.capture == nil {
		writeError(w, r, http.StatusServiceUnavailable, "CAPTURE_UNAVAILABLE", "采集引擎未初始化", nil)
		return
	}
	filename := fmt.Sprintf("scanning-%s.pcap", time.Now().Format("20060102-150405"))
	w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Scanning-Packet-Count", strconv.Itoa(s.capture.Packets().Count()))
	if _, err := s.capture.ExportPCAP(w); err != nil {
		slog.Error("导出 PCAP 失败", "error", err)
	}
}
