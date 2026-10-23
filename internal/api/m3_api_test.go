package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"scanning/internal/blob"
	"scanning/internal/capture"
	"scanning/internal/config"
	"scanning/internal/event"
	"scanning/internal/flow"
	"scanning/internal/store"
)

func newCaptureAPIServer(t *testing.T) (*httptest.Server, *capture.Engine, *store.Ring) {
	t.Helper()
	cfg := config.Default()
	cfg.Demo.Enabled = false
	session := flow.Session{ID: "session-m3-api", Name: "M3 会话", Mode: flow.ModeMixed, CreatedAt: time.Now()}
	st := store.NewRing(100, session.ID)
	hub := event.NewHub(session.ID)
	t.Cleanup(hub.Close)
	blobs, err := blob.New("")
	if err != nil {
		t.Fatal(err)
	}
	captureEngine := capture.New(capture.Config{BufferPackets: 1000, MaxBodyBytes: 1 << 20}, capture.Deps{
		Flows:     st,
		Blobs:     blobs,
		Hub:       hub,
		SessionID: session.ID,
	})
	s := New(Options{
		Config:  cfg,
		Store:   st,
		Hub:     hub,
		Blobs:   blobs,
		Capture: captureEngine,
		Token:   "test-token",
		Session: session,
		Dev:     true,
	})
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return ts, captureEngine, st
}

func TestCaptureStatusAndInterfaces(t *testing.T) {
	ts, _, _ := newCaptureAPIServer(t)

	status, data := doJSON(t, http.MethodGet, ts.URL+"/api/v1/capture/status", nil)
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%s", status, data)
	}
	var envelope struct {
		Data capture.CaptureStatus `json:"data"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Data.Capacity != 1000 {
		t.Fatalf("capacity = %d", envelope.Data.Capacity)
	}

	status, data = doJSON(t, http.MethodGet, ts.URL+"/api/v1/interfaces", nil)
	if status != http.StatusOK {
		t.Fatalf("interfaces status=%d body=%s", status, data)
	}

	status, data = doJSON(t, http.MethodGet, ts.URL+"/api/v1/system/info", nil)
	var info struct {
		Data struct {
			Capture      capture.CaptureStatus `json:"capture"`
			Capabilities map[string]bool       `json:"capabilities"`
		} `json:"data"`
	}
	_ = json.Unmarshal(data, &info)
	if status != http.StatusOK || !info.Data.Capabilities["pcap"] || !info.Data.Capabilities["pcapImport"] {
		t.Fatalf("system info status=%d capabilities=%+v", status, info.Data.Capabilities)
	}

	if !envelope.Data.Available {
		status, data = doJSON(t, http.MethodPost, ts.URL+"/api/v1/capture/start", map[string]any{"interface": "x"})
		if status != http.StatusBadRequest {
			t.Fatalf("start status=%d body=%s", status, data)
		}
	}
}

func TestImportPacketsExportAndClear(t *testing.T) {
	ts, engine, _ := newCaptureAPIServer(t)
	frames := [][]byte{
		buildICMPFrame("10.0.0.1", "10.0.0.2"),
		buildICMPFrame("10.0.0.2", "10.0.0.1"),
	}
	var buf bytes.Buffer
	writer, err := capture.NewPcapWriter(&buf, capture.LinkTypeEthernet)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for _, frame := range frames {
		if err := writer.Write(now, frame, len(frame)); err != nil {
			t.Fatal(err)
		}
	}

	req, err := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/capture/import", bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/vnd.tcpdump.pcap")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("import status=%d body=%s", resp.StatusCode, body)
	}
	var imported struct {
		Data capture.ImportResult `json:"data"`
	}
	if err := json.Unmarshal(body, &imported); err != nil || imported.Data.Packets != 2 {
		t.Fatalf("imported=%s err=%v", body, err)
	}

	status, data := doJSON(t, http.MethodGet, ts.URL+"/api/v1/packets?order=asc&limit=10", nil)
	var list struct {
		Data []capture.PacketSummary `json:"data"`
		Meta struct {
			Total int `json:"total"`
		} `json:"meta"`
	}
	if err := json.Unmarshal(data, &list); err != nil || status != http.StatusOK || len(list.Data) != 2 {
		t.Fatalf("packets status=%d data=%s err=%v", status, data, err)
	}
	if list.Data[0].Protocol != "ICMP" || list.Data[0].SrcIP != "10.0.0.1" {
		t.Fatalf("packet summary = %+v", list.Data[0])
	}

	status, data = doJSON(t, http.MethodGet, ts.URL+"/api/v1/packets/"+list.Data[0].ID, nil)
	if status != http.StatusOK || !bytes.Contains(data, []byte(`"payload"`)) {
		t.Fatalf("packet detail status=%d data=%s", status, data)
	}

	exportResp, err := http.Get(ts.URL + "/api/v1/export/pcap")
	if err != nil {
		t.Fatal(err)
	}
	exported, _ := io.ReadAll(exportResp.Body)
	exportResp.Body.Close()
	if exportResp.StatusCode != http.StatusOK || len(exported) <= 24 || !bytes.Equal(exported[0:4], []byte{0xd4, 0xc3, 0xb2, 0xa1}) {
		t.Fatalf("export status=%d len=%d", exportResp.StatusCode, len(exported))
	}

	status, data = doJSON(t, http.MethodGet, ts.URL+"/api/v1/dns", nil)
	if status != http.StatusOK {
		t.Fatalf("dns status=%d data=%s", status, data)
	}

	status, data = doJSON(t, http.MethodDelete, ts.URL+"/api/v1/packets?confirm=true", nil)
	if status != http.StatusOK {
		t.Fatalf("clear status=%d data=%s", status, data)
	}
	if engine.Packets().Count() != 0 {
		t.Fatalf("packets after clear = %d", engine.Packets().Count())
	}
}

func TestCaptureMirrorToggle(t *testing.T) {
	ts, engine, _ := newCaptureAPIServer(t)
	status, data := doJSON(t, http.MethodPost, ts.URL+"/api/v1/capture/mirror", map[string]any{"enabled": true})
	if status != http.StatusOK {
		t.Fatalf("mirror status=%d body=%s", status, data)
	}
	if !engine.MirrorEnabled() {
		t.Fatal("mirror not enabled")
	}
	status, _ = doJSON(t, http.MethodPost, ts.URL+"/api/v1/capture/mirror", map[string]any{"enabled": false})
	if status != http.StatusOK || engine.MirrorEnabled() {
		t.Fatalf("mirror toggle failed status=%d", status)
	}
}

func buildICMPFrame(srcIP, dstIP string) []byte {
	src := net.ParseIP(srcIP).To4()
	dst := net.ParseIP(dstIP).To4()
	frame := make([]byte, 14+20+8+4)
	frame[12], frame[13] = 0x08, 0x00
	ip := frame[14 : 14+20]
	ip[0] = 0x45
	total := 20 + 8 + 4
	ip[2] = byte(total >> 8)
	ip[3] = byte(total)
	ip[8] = 64
	ip[9] = 1
	copy(ip[12:16], src)
	copy(ip[16:20], dst)
	icmp := frame[34:]
	icmp[0] = 8
	copy(icmp[8:], []byte{1, 2, 3, 4})
	return frame
}
