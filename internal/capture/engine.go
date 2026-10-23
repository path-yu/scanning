package capture

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"scanning/internal/blob"
	"scanning/internal/event"
	"scanning/internal/flow"
	"scanning/internal/store"
)

type Config struct {
	BufferPackets int
	MaxBodyBytes  int64
	Mirror        bool
}

type Deps struct {
	Flows     *store.Ring
	Blobs     *blob.Store
	Hub       *event.Hub
	SessionID string
}

type Engine struct {
	cfg     Config
	deps    Deps
	packets *PacketRing
	dns     *DNSMap
	reasm   *Reassembler
	backend Backend

	opMu sync.Mutex
	mu   sync.Mutex

	running       bool
	source        Source
	cancel        context.CancelFunc
	interfaceName string
	bpf           string
	promisc       bool
	startedAt     time.Time
	lastErr       string
	linkType      int
	mirror        bool

	wg sync.WaitGroup

	packetCount atomic.Int64
	dropped     atomic.Int64
	pcapFlows   atomic.Int64
	mirrored    atomic.Int64
	truncated   atomic.Int64
	bytes       atomic.Int64

	rateMu      sync.Mutex
	lastRateAt  time.Time
	lastRateNum int64
	rate        float64

	flowMu     sync.RWMutex
	flowByConn map[string]string
}

func New(cfg Config, deps Deps) *Engine {
	if cfg.BufferPackets <= 0 {
		cfg.BufferPackets = 20000
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = 10 << 20
	}
	e := &Engine{
		cfg:        cfg,
		deps:       deps,
		packets:    NewPacketRing(cfg.BufferPackets, deps.SessionID),
		dns:        NewDNSMap(),
		backend:    newBackend(),
		linkType:   LinkTypeEthernet,
		mirror:     cfg.Mirror,
		flowByConn: make(map[string]string),
	}
	e.reasm = NewReassembler(e)
	e.reasm.SetMaxBodyBytes(cfg.MaxBodyBytes)
	return e
}

func (e *Engine) Packets() *PacketRing      { return e.packets }
func (e *Engine) DNS() *DNSMap              { return e.dns }
func (e *Engine) Reassembler() *Reassembler { return e.reasm }

func (e *Engine) Status() CaptureStatus {
	e.mu.Lock()
	status := CaptureStatus{
		Running:   e.running,
		Backend:   e.backend.Name(),
		Interface: e.interfaceName,
		BPF:       e.bpf,
		Promisc:   e.promisc,
		Mirror:    e.mirror,
		Error:     e.lastErr,
		LinkType:  e.linkType,
	}
	if e.running && !e.startedAt.IsZero() {
		status.UptimeSec = int64(time.Since(e.startedAt).Seconds())
		if status.UptimeSec < 0 {
			status.UptimeSec = 0
		}
	}
	e.mu.Unlock()

	available, reason := e.backend.Available()
	status.Available = available
	if !available {
		status.Reason = reason
		status.InstallHint = e.backend.InstallHint()
	}
	stats := e.packets.Stats()
	status.Packets = stats.Count
	status.Capacity = stats.Capacity
	status.Flows = int(e.pcapFlows.Load())
	status.DNS = e.dns.Count()
	status.Dropped = e.dropped.Load() + stats.Evicted
	status.Truncated = int64(e.reasm.Truncated())
	status.Rate = e.currentRate(stats.Count)
	return status
}

func (e *Engine) currentRate(count int) float64 {
	e.rateMu.Lock()
	defer e.rateMu.Unlock()
	now := time.Now()
	if e.lastRateAt.IsZero() {
		e.lastRateAt = now
		e.lastRateNum = int64(count)
		return 0
	}
	elapsed := now.Sub(e.lastRateAt).Seconds()
	if elapsed < 0.4 {
		return e.rate
	}
	delta := int64(count) - e.lastRateNum
	e.rate = float64(delta) / elapsed
	e.lastRateAt = now
	e.lastRateNum = int64(count)
	return e.rate
}

func (e *Engine) Interfaces() ([]InterfaceInfo, error) {
	if available, _ := e.backend.Available(); available {
		return e.backend.Interfaces()
	}
	return systemInterfaces(), nil
}

func (e *Engine) SetMirror(enabled bool) {
	e.mu.Lock()
	e.mirror = enabled
	e.mu.Unlock()
}

func (e *Engine) MirrorEnabled() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.mirror
}

func (e *Engine) Start(iface, bpf string, promisc bool) error {
	e.opMu.Lock()
	defer e.opMu.Unlock()

	e.mu.Lock()
	if e.running {
		e.mu.Unlock()
		return errors.New("采集已在运行")
	}
	e.mu.Unlock()

	available, reason := e.backend.Available()
	if !available {
		return fmt.Errorf("实时网卡抓包不可用：%s", reason)
	}
	source, err := e.backend.Open(iface, bpf, promisc)
	if err != nil {
		e.mu.Lock()
		e.lastErr = err.Error()
		e.mu.Unlock()
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	e.mu.Lock()
	e.source = source
	e.cancel = cancel
	e.running = true
	e.interfaceName = iface
	e.bpf = bpf
	e.promisc = promisc
	e.startedAt = time.Now()
	e.lastErr = ""
	e.linkType = source.LinkType()
	e.mu.Unlock()

	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		e.readLoop(ctx, source)
	}()
	slog.Info("网卡采集已启动", "interface", iface, "bpf", bpf, "backend", e.backend.Name())
	return nil
}

func (e *Engine) readLoop(ctx context.Context, source Source) {
	for {
		data, ts, origLen, err := source.Next(ctx)
		if err != nil {
			if ctx.Err() == nil && !errors.Is(err, context.Canceled) {
				e.mu.Lock()
				e.lastErr = err.Error()
				e.running = false
				e.mu.Unlock()
				slog.Warn("网卡采集退出", "error", err)
			}
			return
		}
		e.process(data, ts, origLen)
	}
}

func (e *Engine) Stop(ctx context.Context) error {
	e.opMu.Lock()
	defer e.opMu.Unlock()

	e.mu.Lock()
	if !e.running {
		e.mu.Unlock()
		return nil
	}
	e.running = false
	source := e.source
	cancel := e.cancel
	e.source = nil
	e.cancel = nil
	e.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if source != nil {
		_ = source.Close()
	}

	done := make(chan struct{})
	go func() {
		e.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
	}
	e.reasm.Reset()
	slog.Info("网卡采集已停止")
	return nil
}

func (e *Engine) Import(reader io.Reader, size int64) (ImportResult, error) {
	start := time.Now()
	result := ImportResult{}
	e.opMu.Lock()
	e.mu.Lock()
	if e.running {
		e.mu.Unlock()
		e.opMu.Unlock()
		return result, errors.New("请先停止实时采集再导入 PCAP")
	}
	e.mu.Unlock()
	defer e.opMu.Unlock()

	beforeFlows := e.pcapFlows.Load()
	e.reasm.Reset()
	e.flowMu.Lock()
	e.flowByConn = make(map[string]string)
	e.flowMu.Unlock()

	startPackets := e.packets.Count()
	pcapReader := NewPcapReader(reader)
	first := true
	for {
		record, err := pcapReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			result.Packets = e.packets.Count() - startPackets
			result.Flows = int(e.pcapFlows.Load() - beforeFlows)
			result.Elapsed = time.Since(start).Milliseconds()
			if result.Packets > 0 {
				return result, nil
			}
			return result, err
		}
		if first {
			e.mu.Lock()
			e.linkType = record.LinkType
			e.mu.Unlock()
			first = false
		}
		result.Bytes += int64(len(record.Data))
		e.process(record.Data, record.Timestamp, record.OrigLen)
	}
	if first {
		e.mu.Lock()
		e.linkType = pcapReader.LinkType()
		e.mu.Unlock()
	}
	result.Packets = e.packets.Count() - startPackets
	result.Flows = int(e.pcapFlows.Load() - beforeFlows)
	result.DNS = e.dns.Count()
	result.Elapsed = time.Since(start).Milliseconds()
	_ = size
	return result, nil
}

func (e *Engine) process(raw []byte, ts time.Time, origLen int) {
	if len(raw) == 0 {
		return
	}
	e.mu.Lock()
	linkType := e.linkType
	e.mu.Unlock()
	dec, err := Decode(linkType, raw)
	if err != nil {
		e.dropped.Add(1)
		return
	}
	p := &Packet{
		Timestamp:  ts,
		CaptureLen: len(raw),
		OrigLen:    origLen,
		LinkType:   linkType,
		SrcIP:      dec.SrcIP,
		DstIP:      dec.DstIP,
		SrcPort:    dec.SrcPort,
		DstPort:    dec.DstPort,
		Protocol:   dec.Protocol,
		TCP:        dec.TCP,
		DNS:        dec.DNS,
		TLS:        dec.TLS,
		Raw:        raw,
	}
	if len(dec.Payload) > 0 {
		preview := dec.Payload
		if len(preview) > 4096 {
			preview = preview[:4096]
		}
		p.Payload = append([]byte(nil), preview...)
	}
	p.Host = e.hostForPacket(dec)
	p.Summary = summarizePacket(dec)
	if dec.Protocol == "TCP" && dec.TCP != nil {
		client, server := guessEndpoints(dec, dec.TCP.Flags)
		key := connKey(client, server)
		e.flowMu.RLock()
		p.FlowID = e.flowByConn[key]
		e.flowMu.RUnlock()
	}
	e.packets.Add(p)
	e.packetCount.Add(1)
	e.bytes.Add(int64(len(raw)))
	e.ingestDNS(dec, time.Now())
	e.reasm.Assemble(dec, ts, origLen)
}

func (e *Engine) hostForPacket(dec *Decoded) string {
	if dec.TLS != nil && dec.TLS.SNI != "" {
		return dec.TLS.SNI
	}
	if dec.DNS != nil && dec.DNS.Question != "" {
		return dec.DNS.Question
	}
	if names := e.dns.LookupIP(dec.DstIP); len(names) > 0 {
		return names[0]
	}
	if names := e.dns.LookupIP(dec.SrcIP); len(names) > 0 {
		return names[0]
	}
	return ""
}

func (e *Engine) ingestDNS(dec *Decoded, ts time.Time) {
	if dec.DNS == nil || dec.DNS.QR != "response" || dec.DNS.Question == "" {
		return
	}
	for _, ip := range dec.DNS.Answers {
		ttl := dec.DNS.TTL
		// 被动观测的 DNS 映射至少保留 5 分钟，便于回看导入的历史抓包。
		if ttl < 300 {
			ttl = 300
		}
		e.dns.Add(dec.DNS.Question, ip, ttl, ts)
	}
}

func (e *Engine) ExportPCAP(w interface{ Write([]byte) (int, error) }) (int, error) {
	items := e.packets.All()
	e.mu.Lock()
	linkType := e.linkType
	e.mu.Unlock()
	if len(items) > 0 && items[0].LinkType > 0 {
		linkType = items[0].LinkType
	}
	if linkType <= 0 {
		linkType = LinkTypeEthernet
	}
	writer, err := NewPcapWriter(w, linkType)
	if err != nil {
		return 0, err
	}
	written := 0
	for _, p := range items {
		if len(p.Raw) == 0 {
			continue
		}
		if err := writer.Write(p.Timestamp, p.Raw, p.OrigLen); err != nil {
			return written, err
		}
		written++
	}
	return written, nil
}

func (e *Engine) ClearPackets() int {
	count := e.packets.Clear()
	e.reasm.Reset()
	e.dns.Clear()
	e.mirrored.Store(0)
	e.dropped.Store(0)
	e.flowMu.Lock()
	e.flowByConn = make(map[string]string)
	e.flowMu.Unlock()
	return count
}

// EmitFlow 实现 Sink 接口。
func (e *Engine) EmitFlow(f *flow.Flow) string {
	if f == nil {
		return ""
	}
	f.Mode = flow.ModePCAP
	added := e.deps.Flows.Add(f)
	if added == nil {
		return ""
	}
	e.pcapFlows.Add(1)
	if e.deps.Hub != nil {
		e.deps.Hub.Broadcast("flow.created", added.Summary())
	}
	return added.ID
}

// MakeBody 实现 Sink 接口，保存完整正文并生成预览。
func (e *Engine) MakeBody(data []byte, mime, encoding string) *flow.Body {
	if len(data) == 0 {
		return nil
	}
	ref, err := e.deps.Blobs.Put(data)
	if err != nil {
		slog.Warn("保存网卡正文失败", "error", err)
	}
	text, preview := decodePreview(data, encoding, mime)
	return &flow.Body{
		Ref:          ref,
		Size:         int64(len(data)),
		CapturedSize: int64(len(data)),
		Mime:         mime,
		Encoding:     encoding,
		Text:         text,
		Preview:      preview,
	}
}

// AttachFlow 实现 Sink 接口。
func (e *Engine) AttachFlow(key ConnKey, flowID string) {
	e.packets.AttachFlow(key.ClientIP, key.ClientPort, key.ServerIP, key.ServerPort, flowID)
	a := endpoint{ip: key.ClientIP, port: key.ClientPort}
	b := endpoint{ip: key.ServerIP, port: key.ServerPort}
	e.flowMu.Lock()
	e.flowByConn[connKey(a, b)] = flowID
	e.flowMu.Unlock()
}

// HostFor 实现 Sink 接口。
func (e *Engine) HostFor(ip string) string {
	if names := e.dns.LookupIP(ip); len(names) > 0 {
		return names[0]
	}
	return ""
}

func decodePreview(data []byte, encoding, mime string) (bool, string) {
	raw := blob.DecodeLimited(data, encoding, 64<<10)
	if len(raw) == 0 {
		return false, ""
	}
	if !isTextMime(mime) && !looksLikeText(raw) {
		return false, ""
	}
	for len(raw) > 0 && !utf8.Valid(raw) {
		raw = raw[:len(raw)-1]
	}
	if len(raw) > 2048 {
		raw = raw[:2048]
	}
	for len(raw) > 0 && !utf8.Valid(raw) {
		raw = raw[:len(raw)-1]
	}
	if len(raw) == 0 {
		return false, ""
	}
	return true, string(raw)
}

func isTextMime(mime string) bool {
	mime = strings.ToLower(mime)
	return strings.HasPrefix(mime, "text/") ||
		strings.Contains(mime, "json") ||
		strings.Contains(mime, "javascript") ||
		strings.Contains(mime, "xml") ||
		strings.Contains(mime, "x-www-form-urlencoded") ||
		strings.Contains(mime, "graphql") ||
		strings.Contains(mime, "svg")
}

func looksLikeText(data []byte) bool {
	if bytes.IndexByte(data, 0) >= 0 {
		return false
	}
	kind := http.DetectContentType(data)
	return strings.HasPrefix(kind, "text/") || strings.Contains(kind, "json") || strings.Contains(kind, "xml")
}

func summarizePacket(dec *Decoded) string {
	if dec == nil {
		return ""
	}
	if dec.DNS != nil {
		dns := dec.DNS
		if dns.QR == "response" {
			return fmt.Sprintf("DNS response %s %s · %d answers", dns.Question, dns.RCode, len(dns.Answers))
		}
		return fmt.Sprintf("DNS query %s %s", dns.Question, dns.QType)
	}
	if dec.TLS != nil {
		if dec.TLS.SNI != "" {
			return "TLS ClientHello · " + dec.TLS.SNI
		}
		return "TLS ClientHello"
	}
	if dec.Protocol != "TCP" {
		if dec.SrcPort > 0 || dec.DstPort > 0 {
			return fmt.Sprintf("%s %d → %d · %d B", dec.Protocol, dec.SrcPort, dec.DstPort, len(dec.Payload))
		}
		return dec.Protocol
	}
	flags := ""
	if dec.TCP != nil {
		flags = dec.TCP.Flags
	}
	line := firstHTTPLine(dec.Payload)
	if line != "" {
		return line
	}
	if flags == "SYN" || flags == "SYN,ACK" || flags == "ACK" || flags == "FIN,ACK" || flags == "RST" {
		return "TCP " + flags
	}
	return fmt.Sprintf("TCP %s · %d B", flags, len(dec.Payload))
}

func firstHTTPLine(payload []byte) string {
	if len(payload) == 0 {
		return ""
	}
	end := bytes.Index(payload, []byte("\r\n"))
	if end < 0 {
		end = len(payload)
	}
	if end > 120 {
		end = 120
	}
	line := string(payload[:end])
	upper := strings.ToUpper(line)
	for _, prefix := range []string{"GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "OPTIONS ", "PATCH "} {
		if strings.HasPrefix(upper, prefix) {
			return line
		}
	}
	if strings.HasPrefix(line, "HTTP/") {
		return line
	}
	return ""
}
