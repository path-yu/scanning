package capture

import (
	"bytes"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"

	"scanning/internal/blob"
	"scanning/internal/event"
	"scanning/internal/flow"
	"scanning/internal/store"
)

func newCaptureEngine(t *testing.T) (*Engine, *store.Ring, *blob.Store) {
	t.Helper()
	st := store.NewRing(100, "session-m3")
	hub := event.NewHub("session-m3")
	t.Cleanup(hub.Close)
	blobs, err := blob.New("")
	if err != nil {
		t.Fatal(err)
	}
	engine := New(Config{BufferPackets: 1000, MaxBodyBytes: 1 << 20}, Deps{
		Flows:     st,
		Blobs:     blobs,
		Hub:       hub,
		SessionID: "session-m3",
	})
	return engine, st, blobs
}

type frameRecord struct {
	ts   time.Time
	data []byte
}

func pcapFromFrames(t *testing.T, frames []frameRecord) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer, err := NewPcapWriter(&buf, LinkTypeEthernet)
	if err != nil {
		t.Fatal(err)
	}
	for _, frame := range frames {
		if err := writer.Write(frame.ts, frame.data, len(frame.data)); err != nil {
			t.Fatal(err)
		}
	}
	return buf.Bytes()
}

func TestPcapRoundTrip(t *testing.T) {
	now := time.Now()
	payloadA := []byte{1, 2, 3}
	payloadB := []byte{4, 5, 6, 7}
	pcap := pcapFromFrames(t, []frameRecord{
		{ts: now, data: payloadA},
		{ts: now.Add(time.Millisecond), data: payloadB},
	})

	reader := NewPcapReader(bytes.NewReader(pcap))
	if reader.LinkType() != LinkTypeEthernet {
		t.Fatalf("link type = %d", reader.LinkType())
	}
	first, err := reader.Next()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Data, payloadA) || first.Timestamp.UnixNano()/1e6 != now.UnixNano()/1e6 {
		t.Fatalf("first record = %+v", first)
	}
	second, err := reader.Next()
	if err != nil || !bytes.Equal(second.Data, payloadB) {
		t.Fatalf("second = %+v err=%v", second, err)
	}
	if _, err := reader.Next(); err == nil {
		t.Fatal("expected EOF")
	}

	ng := []byte{0x0a, 0x0d, 0x0d, 0x0a, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	ngReader := NewPcapReader(bytes.NewReader(ng))
	if _, err := ngReader.Next(); err == nil || !strings.Contains(err.Error(), "pcapng") {
		t.Fatalf("pcapng error = %v", err)
	}
}

func TestImportHTTPReassembly(t *testing.T) {
	engine, st, _ := newCaptureEngine(t)
	start := time.Now()
	client := "10.0.0.1"
	server := "10.0.0.2"
	clientPort := 12345
	serverPort := 80

	request := []byte("GET /hello?x=1 HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n")
	response := []byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\n\r\n{\"ok\":true}")

	seqC := uint32(100)
	seqS := uint32(500)
	frames := []frameRecord{
		{ts: start, data: buildTCPFrame(client, server, clientPort, serverPort, seqC, 0, 0x02, nil)},
		{ts: start.Add(1 * time.Millisecond), data: buildTCPFrame(server, client, serverPort, clientPort, seqS, seqC+1, 0x12, nil)},
		{ts: start.Add(2 * time.Millisecond), data: buildTCPFrame(client, server, clientPort, serverPort, seqC+1, seqS+1, 0x10, nil)},
		{ts: start.Add(3 * time.Millisecond), data: buildTCPFrame(client, server, clientPort, serverPort, seqC+1, seqS+1, 0x18, request)},
		{ts: start.Add(4 * time.Millisecond), data: buildTCPFrame(server, client, serverPort, clientPort, seqS+1, seqC+1+uint32(len(request)), 0x18, response)},
		{ts: start.Add(5 * time.Millisecond), data: buildTCPFrame(client, server, clientPort, serverPort, seqC+1+uint32(len(request)), seqS+1+uint32(len(response)), 0x10, nil)},
	}
	pcap := pcapFromFrames(t, frames)

	result, err := engine.Import(bytes.NewReader(pcap), int64(len(pcap)))
	if err != nil {
		t.Fatal(err)
	}
	if result.Packets != len(frames) {
		t.Fatalf("packets = %d", result.Packets)
	}
	if result.Flows != 1 {
		t.Fatalf("flows = %d", result.Flows)
	}

	items := st.All()
	if len(items) != 1 {
		t.Fatalf("stored flows = %d", len(items))
	}
	f := items[0]
	if f.Mode != flow.ModePCAP || f.Method != "GET" || f.Path != "/hello?x=1" {
		t.Fatalf("flow = %+v", f)
	}
	if f.Host != "example.com" || f.StatusCode != 200 || f.Mime != "application/json" {
		t.Fatalf("flow meta = %+v", f)
	}
	if f.Response == nil || f.Response.Body == nil || !strings.Contains(f.Response.Body.Preview, `"ok":true`) {
		t.Fatalf("response body = %+v", f.Response)
	}
	if f.Request == nil || f.Request.Body != nil {
		t.Fatalf("request body = %+v", f.Request)
	}
	if f.Server.IP != server || f.Client.IP != client {
		t.Fatalf("endpoints = %+v %+v", f.Client, f.Server)
	}

	packets := engine.Packets().All()
	linked := 0
	for _, p := range packets {
		if p.FlowID == f.ID {
			linked++
		}
		if p.Protocol != "TCP" || p.TCP == nil {
			t.Fatalf("packet decode = %+v", p)
		}
	}
	if linked < 2 {
		t.Fatalf("linked packets = %d", linked)
	}

	// 导出的 pcap 应能被再次读取。
	var exported bytes.Buffer
	count, err := engine.ExportPCAP(&exported)
	if err != nil || count != len(frames) {
		t.Fatalf("export count=%d err=%v", count, err)
	}
	reader := NewPcapReader(bytes.NewReader(exported.Bytes()))
	for i := 0; i < len(frames); i++ {
		if _, err := reader.Next(); err != nil {
			t.Fatalf("exported record %d: %v", i, err)
		}
	}
}

func TestDNSDecodeAndMapping(t *testing.T) {
	engine, _, _ := newCaptureEngine(t)
	query := buildDNSResponse(t)
	frame := buildUDPFrame("10.0.0.1", "8.8.8.8", 5353, 53, query)
	engine.process(frame, time.Now(), len(frame))

	packets := engine.Packets().All()
	if len(packets) != 1 {
		t.Fatalf("packets = %d", len(packets))
	}
	p := packets[0]
	if p.Protocol != "UDP" || p.DNS == nil {
		t.Fatalf("packet = %+v", p)
	}
	if p.DNS.Question != "api.example.com" || p.DNS.QType != "A" || len(p.DNS.Answers) != 1 {
		t.Fatalf("dns = %+v", p.DNS)
	}
	if p.DNS.Answers[0] != "93.184.216.34" || p.DNS.TTL != 60 {
		t.Fatalf("dns answers = %+v", p.DNS)
	}
	if !strings.Contains(p.Summary, "DNS response api.example.com") {
		t.Fatalf("summary = %s", p.Summary)
	}
	if got := engine.HostFor("93.184.216.34"); got != "api.example.com" {
		t.Fatalf("host = %q", got)
	}
	entries := engine.DNS().Entries(10)
	if len(entries) != 1 || entries[0].Domain != "api.example.com" {
		t.Fatalf("entries = %+v", entries)
	}
}

func TestMirrorFlowPackets(t *testing.T) {
	engine, _, _ := newCaptureEngine(t)
	now := time.Now()
	reqBody := engine.MakeBody([]byte(`{"a":1}`), "application/json", "")
	respBody := engine.MakeBody([]byte(`{"ok":true}`), "application/json", "")
	f := &flow.Flow{
		ID:         "flow-mirror-1",
		Mode:       flow.ModeProxy,
		State:      flow.StateCompleted,
		Scheme:     "http",
		Host:       "example.com",
		Port:       80,
		Method:     "POST",
		Path:       "/mirror",
		StatusCode: 201,
		Mime:       "application/json",
		ReqSize:    7,
		RespSize:   11,
		Client:     flow.ClientInfo{IP: "10.1.0.1", Port: 40000},
		Server:     flow.ServerInfo{IP: "93.184.216.34", Port: 80, Name: "example.com"},
		Request: &flow.Message{
			HTTPVersion: "HTTP/1.1",
			Headers:     flow.Headers{{Name: "Host", Value: "example.com"}, {Name: "Content-Type", Value: "application/json"}},
			Body:        reqBody,
		},
		Response: &flow.Message{
			HTTPVersion: "HTTP/1.1",
			Headers:     flow.Headers{{Name: "Content-Type", Value: "application/json"}},
			Body:        respBody,
		},
		StartedAt:   now,
		CompletedAt: timePtr(now.Add(10 * time.Millisecond)),
	}

	engine.SetMirror(true)
	engine.MirrorFlow(f)
	packets := engine.Packets().All()
	if len(packets) < 7 {
		t.Fatalf("mirror packets = %d", len(packets))
	}
	sawRequest := false
	sawResponse := false
	for _, p := range packets {
		if p.FlowID != f.ID || p.Protocol != "TCP" {
			t.Fatalf("packet = %+v", p)
		}
		if strings.Contains(p.Summary, "HTTP 请求") {
			sawRequest = true
		}
		if strings.Contains(p.Summary, "HTTP 响应") {
			sawResponse = true
		}
	}
	if !sawRequest || !sawResponse {
		t.Fatalf("missing HTTP summaries: req=%v resp=%v", sawRequest, sawResponse)
	}

	var buf bytes.Buffer
	count, err := engine.ExportPCAP(&buf)
	if err != nil || count != len(packets) {
		t.Fatalf("export count=%d err=%v", count, err)
	}
}

func timePtr(t time.Time) *time.Time { return &t }

func buildDNSResponse(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	buf.Write([]byte{0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00})
	writeDNSName(&buf, "api.example.com")
	buf.Write([]byte{0x00, 0x01, 0x00, 0x01}) // A IN
	buf.Write([]byte{0xc0, 0x0c})             // pointer to question
	buf.Write([]byte{0x00, 0x01, 0x00, 0x01})
	ttl := make([]byte, 4)
	binary.BigEndian.PutUint32(ttl, 60)
	buf.Write(ttl)
	buf.Write([]byte{0x00, 0x04, 93, 184, 216, 34})
	return buf.Bytes()
}

func writeDNSName(buf *bytes.Buffer, name string) {
	for _, label := range strings.Split(name, ".") {
		buf.WriteByte(byte(len(label)))
		buf.WriteString(label)
	}
	buf.WriteByte(0)
}

func buildUDPFrame(srcIP, dstIP string, sport, dport int, payload []byte) []byte {
	src := net.ParseIP(srcIP).To4()
	dst := net.ParseIP(dstIP).To4()
	frame := make([]byte, 14+20+8+len(payload))
	frame[12], frame[13] = 0x08, 0x00
	ip := frame[14 : 14+20]
	ip[0] = 0x45
	total := 20 + 8 + len(payload)
	ip[2] = byte(total >> 8)
	ip[3] = byte(total)
	ip[8] = 64
	ip[9] = 17
	copy(ip[12:16], src)
	copy(ip[16:20], dst)
	udp := frame[34:]
	udp[0] = byte(sport >> 8)
	udp[1] = byte(sport)
	udp[2] = byte(dport >> 8)
	udp[3] = byte(dport)
	udpLen := 8 + len(payload)
	udp[4] = byte(udpLen >> 8)
	udp[5] = byte(udpLen)
	copy(udp[8:], payload)
	return frame
}
