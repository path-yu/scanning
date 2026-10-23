package capture

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"scanning/internal/flow"
)

type ConnKey struct {
	ClientIP   string
	ClientPort int
	ServerIP   string
	ServerPort int
}

type Sink interface {
	// EmitFlow 将重组出的 HTTP Flow 写入存储并返回 Flow ID。
	EmitFlow(f *flow.Flow) string
	// MakeBody 保存正文并生成预览。
	MakeBody(data []byte, mime, encoding string) *flow.Body
	// AttachFlow 把连接上的报文关联到 Flow。
	AttachFlow(key ConnKey, flowID string)
	// HostFor 通过 DNS 映射反查 IP 对应的域名。
	HostFor(ip string) string
}

type httpRequest struct {
	method  string
	host    string
	path    string
	proto   string
	headers http.Header
	body    []byte
	at      time.Time
}

type httpResponse struct {
	status      int
	proto       string
	headers     http.Header
	body        []byte
	contentType string
	at          time.Time
}

type tcpStream struct {
	init      bool
	nextSeq   uint32
	segments  map[uint32][]byte
	buf       []byte
	truncated bool
	lastAt    time.Time
}

type connState struct {
	client  endpoint
	server  endpoint
	streams [2]*tcpStream

	firstSeen time.Time
	lastSeen  time.Time

	decision int // 0 未决定；1 HTTP；2 非 HTTP
	tls      *TLSMeta
	upgraded bool

	requests  []*httpRequest
	responses []*httpResponse
}

type endpoint struct {
	ip   string
	port int
}

func (e endpoint) valid() bool { return e.ip != "" }

type Reassembler struct {
	mu             sync.Mutex
	sink           Sink
	conns          map[string]*connState
	maxConns       int
	maxStreamBytes int
	maxBodyBytes   int64
	packetCount    int
	flowCount      int
	truncated      int
}

func NewReassembler(sink Sink) *Reassembler {
	return &Reassembler{
		sink:           sink,
		conns:          make(map[string]*connState),
		maxConns:       10000,
		maxStreamBytes: 8 << 20,
		maxBodyBytes:   10 << 20,
	}
}

func (r *Reassembler) SetMaxBodyBytes(n int64) {
	if n > 0 {
		r.maxBodyBytes = n
	}
}

func (r *Reassembler) Flows() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.flowCount
}

func (r *Reassembler) Truncated() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.truncated
}

// Reset 清空重组状态（导入新文件或停止采集时调用）。
func (r *Reassembler) Reset() {
	r.mu.Lock()
	r.conns = make(map[string]*connState)
	r.packetCount = 0
	r.truncated = 0
	r.mu.Unlock()
}

func (r *Reassembler) Assemble(dec *Decoded, ts time.Time, origLen int) {
	if dec == nil || dec.Protocol != "TCP" || dec.TCP == nil {
		return
	}
	client, server := guessEndpoints(dec, dec.TCP.Flags)
	if !client.valid() || !server.valid() {
		return
	}
	key := connKey(client, server)
	side := 0
	src := endpoint{ip: dec.SrcIP, port: dec.SrcPort}
	if src == server {
		side = 1
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	conn := r.conns[key]
	if conn == nil {
		conn = &connState{
			client:    client,
			server:    server,
			streams:   [2]*tcpStream{{}, {}},
			firstSeen: ts,
			lastSeen:  ts,
		}
		if len(r.conns) >= r.maxConns {
			r.evictOldestLocked()
		}
		r.conns[key] = conn
	}
	if conn.firstSeen.IsZero() {
		conn.firstSeen = ts
	}
	conn.lastSeen = ts
	stream := conn.streams[side]
	stream.lastAt = ts

	if strings.Contains(dec.TCP.Flags, "SYN") && !strings.Contains(dec.TCP.Flags, "ACK") {
		stream.init = true
		stream.nextSeq = dec.TCP.Seq + 1
	}
	if dec.TCP.Flags == "-" || dec.Payload == nil {
		return
	}
	if len(dec.Payload) == 0 || conn.decision == 2 || conn.upgraded {
		return
	}
	if !stream.init {
		stream.init = true
		stream.nextSeq = dec.TCP.Seq
	}
	if !stream.push(dec.TCP.Seq, dec.Payload, r.maxStreamBytes) {
		return
	}

	switch conn.decision {
	case 0:
		if side == 0 {
			decideHTTP(conn, stream, r.maxStreamBytes)
			if conn.decision != 1 {
				return
			}
			r.parseRequestsLocked(conn, ts)
		}
	case 1:
		if side == 0 {
			r.parseRequestsLocked(conn, ts)
		} else {
			r.parseResponsesLocked(conn, ts)
		}
	}
	r.packetCount++
	if r.packetCount%500 == 0 {
		r.cleanupLocked(ts)
	}
}

func (s *tcpStream) push(seq uint32, payload []byte, limit int) bool {
	if len(payload) == 0 || s.truncated {
		return false
	}
	if seq < s.nextSeq {
		delta := s.nextSeq - seq
		if int(delta) >= len(payload) {
			return false
		}
		payload = payload[delta:]
		seq = s.nextSeq
	}
	appended := false
	if seq == s.nextSeq {
		s.append(payload, limit)
		s.nextSeq += uint32(len(payload))
		appended = true
		if s.segments != nil {
			for {
				seg, ok := s.segments[s.nextSeq]
				if !ok {
					break
				}
				s.append(seg, limit)
				s.nextSeq += uint32(len(seg))
				delete(s.segments, s.nextSeq-uint32(len(seg)))
			}
		}
	} else {
		if s.segments == nil {
			s.segments = make(map[uint32][]byte)
		}
		if len(s.segments) < 256 {
			cp := make([]byte, len(payload))
			copy(cp, payload)
			s.segments[seq] = cp
		}
	}
	return appended
}

func (s *tcpStream) append(data []byte, limit int) {
	if limit <= 0 {
		limit = 8 << 20
	}
	s.buf = append(s.buf, data...)
	if len(s.buf) > limit {
		s.buf = s.buf[:limit]
		s.truncated = true
	}
}

func decideHTTP(conn *connState, stream *tcpStream, limit int) {
	if len(stream.buf) == 0 {
		return
	}
	first := stream.buf
	if len(first) >= 5 && first[0] == 0x16 {
		if tls := parseTLSClientHello(first); tls != nil {
			conn.tls = tls
		}
		conn.decision = 2
		stream.buf = nil
		return
	}
	for _, method := range []string{"GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE "} {
		if bytes.HasPrefix(first, []byte(method)) {
			conn.decision = 1
			return
		}
	}
	if len(first) >= 8 {
		conn.decision = 2
		stream.buf = nil
	}
}

func (r *Reassembler) parseRequestsLocked(conn *connState, at time.Time) {
	stream := conn.streams[0]
	for len(stream.buf) > 0 && len(conn.requests) < 64 {
		req, consumed, ok := parseOneRequest(stream.buf, r.maxBodyBytes)
		if !ok {
			break
		}
		req.at = at
		stream.buf = stream.buf[consumed:]
		conn.requests = append(conn.requests, req)
		r.tryEmitLocked(conn)
	}
	if len(stream.buf) > r.maxStreamBytes {
		stream.buf = nil
		stream.truncated = true
		r.truncated++
	}
}

func (r *Reassembler) parseResponsesLocked(conn *connState, at time.Time) {
	stream := conn.streams[1]
	for len(stream.buf) > 0 && len(conn.responses) < 64 {
		var protoReq *http.Request
		if len(conn.requests) > 0 {
			req := conn.requests[0]
			protoReq = &http.Request{Method: req.method}
		}
		resp, consumed, ok := parseOneResponse(stream.buf, protoReq, r.maxBodyBytes)
		if !ok {
			break
		}
		resp.at = at
		stream.buf = stream.buf[consumed:]
		conn.responses = append(conn.responses, resp)
		if resp.status == http.StatusSwitchingProtocols {
			conn.upgraded = true
		}
		r.tryEmitLocked(conn)
	}
	if len(stream.buf) > r.maxStreamBytes {
		stream.buf = nil
		stream.truncated = true
		r.truncated++
	}
}

func (r *Reassembler) tryEmitLocked(conn *connState) {
	for len(conn.requests) > 0 && len(conn.responses) > 0 {
		req := conn.requests[0]
		resp := conn.responses[0]
		conn.requests = conn.requests[1:]
		conn.responses = conn.responses[1:]
		r.emitLocked(conn, req, resp)
	}
}

func (r *Reassembler) emitLocked(conn *connState, req *httpRequest, resp *httpResponse) {
	host := req.host
	if host == "" && conn.tls != nil {
		host = conn.tls.SNI
	}
	if host == "" {
		host = r.sink.HostFor(conn.server.ip)
	}
	if host == "" {
		host = conn.server.ip
	}
	if req.method == "" {
		req.method = "GET"
	}
	if req.path == "" {
		req.path = "/"
	}
	if req.proto == "" {
		req.proto = "HTTP/1.1"
	}
	completed := resp.at
	if completed.IsZero() {
		completed = req.at
	}
	if completed.IsZero() {
		completed = conn.lastSeen
	}
	started := req.at
	if started.IsZero() {
		started = conn.firstSeen
	}
	if completed.Before(started) {
		completed = started
	}
	contentType := resp.contentType
	f := &flow.Flow{
		Mode:       flow.ModePCAP,
		State:      flow.StateCompleted,
		Scheme:     "http",
		Host:       host,
		Port:       conn.server.port,
		Method:     req.method,
		Path:       req.path,
		StatusCode: resp.status,
		Mime:       contentType,
		ReqSize:    int64(len(req.body)),
		RespSize:   int64(len(resp.body)),
		DurationMs: completed.Sub(started).Milliseconds(),
		Client:     flow.ClientInfo{IP: conn.client.ip, Port: conn.client.port, Origin: "pcap"},
		Server:     flow.ServerInfo{IP: conn.server.ip, Port: conn.server.port, Name: host},
		Request: &flow.Message{
			HTTPVersion: req.proto,
			Headers:     headersFromHTTP(req.headers, req.host),
			Body:        r.sink.MakeBody(req.body, req.headers.Get("Content-Type"), req.headers.Get("Content-Encoding")),
		},
		Response: &flow.Message{
			HTTPVersion: resp.proto,
			Headers:     headersFromHTTP(resp.headers, ""),
			Body:        r.sink.MakeBody(resp.body, contentType, resp.headers.Get("Content-Encoding")),
		},
		Tags:      []string{"pcap"},
		StartedAt: started,
	}
	f.CompletedAt = &completed
	if id := r.sink.EmitFlow(f); id != "" {
		r.sink.AttachFlow(ConnKey{
			ClientIP:   conn.client.ip,
			ClientPort: conn.client.port,
			ServerIP:   conn.server.ip,
			ServerPort: conn.server.port,
		}, id)
		r.flowCount++
	}
}

func (r *Reassembler) evictOldestLocked() {
	var oldestKey string
	var oldest time.Time
	for key, conn := range r.conns {
		if oldestKey == "" || conn.lastSeen.Before(oldest) {
			oldestKey = key
			oldest = conn.lastSeen
		}
	}
	if oldestKey != "" {
		delete(r.conns, oldestKey)
	}
}

func (r *Reassembler) cleanupLocked(now time.Time) {
	cutoff := now.Add(-2 * time.Minute)
	for key, conn := range r.conns {
		if conn.lastSeen.Before(cutoff) {
			delete(r.conns, key)
		}
	}
}

func guessEndpoints(dec *Decoded, flags string) (client, server endpoint) {
	src := endpoint{ip: dec.SrcIP, port: dec.SrcPort}
	dst := endpoint{ip: dec.DstIP, port: dec.DstPort}
	switch {
	case strings.Contains(flags, "SYN") && !strings.Contains(flags, "ACK"):
		return src, dst
	case strings.Contains(flags, "SYN") && strings.Contains(flags, "ACK"):
		return dst, src
	}
	if httpPort(dst.port) && !httpPort(src.port) {
		return src, dst
	}
	if httpPort(src.port) && !httpPort(dst.port) {
		return dst, src
	}
	if dst.port < src.port {
		return src, dst
	}
	return dst, src
}

func httpPort(port int) bool {
	switch port {
	case 80, 3000, 5000, 8000, 8008, 8080, 8081, 8880, 8888, 9000, 9090:
		return true
	default:
		return false
	}
}

func connKey(client, server endpoint) string {
	a, b := client, server
	if endpointLess(b, a) {
		a, b = b, a
	}
	return a.ip + "|" + itoa(a.port) + "|" + b.ip + "|" + itoa(b.port)
}

func endpointLess(a, b endpoint) bool {
	if a.ip == b.ip {
		return a.port < b.port
	}
	return a.ip < b.ip
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var buf [12]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}

func headersFromHTTP(headers http.Header, host string) flow.Headers {
	names := make([]string, 0, len(headers)+1)
	for name := range headers {
		names = append(names, name)
	}
	if host != "" {
		names = append(names, "Host")
	}
	sort.Strings(names)
	out := make(flow.Headers, 0, len(names))
	for _, name := range names {
		if strings.EqualFold(name, "Host") && host != "" {
			out = append(out, flow.Header{Name: "Host", Value: host})
			continue
		}
		for _, value := range headers.Values(name) {
			out = append(out, flow.Header{Name: name, Value: value})
		}
	}
	return out
}

type countingReader struct {
	r *bytes.Reader
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

func parseOneRequest(buf []byte, maxBody int64) (*httpRequest, int, bool) {
	cr := &countingReader{r: bytes.NewReader(buf)}
	br := bufio.NewReaderSize(cr, 64<<10)
	req, err := http.ReadRequest(br)
	if err != nil {
		return nil, 0, false
	}
	body, readErr := readLimitedBody(req.Body, maxBody)
	_ = req.Body.Close()
	if readErr != nil {
		return nil, 0, false
	}
	consumed := cr.n - br.Buffered()
	if consumed <= 0 || consumed > len(buf) {
		return nil, 0, false
	}
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	path := req.URL.RequestURI()
	if path == "" {
		path = req.RequestURI
	}
	return &httpRequest{
		method:  req.Method,
		host:    host,
		path:    path,
		proto:   req.Proto,
		headers: req.Header.Clone(),
		body:    body,
	}, consumed, true
}

func parseOneResponse(buf []byte, protoReq *http.Request, maxBody int64) (*httpResponse, int, bool) {
	if protoReq == nil {
		protoReq = &http.Request{Method: http.MethodGet}
	}
	cr := &countingReader{r: bytes.NewReader(buf)}
	br := bufio.NewReaderSize(cr, 64<<10)
	resp, err := http.ReadResponse(br, protoReq)
	if err != nil {
		return nil, 0, false
	}
	body, readErr := readLimitedBody(resp.Body, maxBody)
	_ = resp.Body.Close()
	if readErr != nil {
		return nil, 0, false
	}
	consumed := cr.n - br.Buffered()
	if consumed <= 0 || consumed > len(buf) {
		return nil, 0, false
	}
	return &httpResponse{
		status:      resp.StatusCode,
		proto:       resp.Proto,
		headers:     resp.Header.Clone(),
		body:        body,
		contentType: resp.Header.Get("Content-Type"),
	}, consumed, true
}

func readLimitedBody(body io.Reader, limit int64) ([]byte, error) {
	if body == nil || body == http.NoBody {
		return nil, nil
	}
	if limit <= 0 {
		limit = 10 << 20
	}
	data, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
			return nil, io.ErrUnexpectedEOF
		}
		return nil, err
	}
	if int64(len(data)) > limit {
		data = data[:limit]
	}
	return data, nil
}
