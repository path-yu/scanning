package export

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"scanning/internal/flow"
)

func TestBuildHAR(t *testing.T) {
	started := time.Date(2026, 10, 23, 10, 0, 0, 0, time.UTC)
	completed := started.Add(120 * time.Millisecond)
	f := &flow.Flow{
		ID:         "f1",
		Scheme:     "https",
		Host:       "api.example.com",
		Port:       443,
		Method:     "POST",
		Path:       "/v1/orders?q=1",
		StatusCode: 201,
		Mime:       "application/json",
		ReqSize:    20,
		RespSize:   30,
		DurationMs: 120,
		Client:     flow.ClientInfo{IP: "127.0.0.1", Port: 54321, App: "chrome.exe"},
		Server:     flow.ServerInfo{IP: "93.184.216.34", Port: 443},
		Request: &flow.Message{
			HTTPVersion: "HTTP/1.1",
			Headers:     flow.Headers{{Name: "Content-Type", Value: "application/json"}, {Name: "Host", Value: "api.example.com"}},
			Body:        &flow.Body{Size: 20, CapturedSize: 20, Mime: "application/json", Text: true, Preview: `{"sku":"a"}`},
		},
		Response: &flow.Message{
			HTTPVersion: "HTTP/1.1",
			Headers:     flow.Headers{{Name: "Content-Type", Value: "application/json"}, {Name: "Set-Cookie", Value: "a=b"}},
			Body:        &flow.Body{Size: 30, CapturedSize: 30, Mime: "application/json", Text: true, Preview: `{"id":1}`},
		},
		Timing:      &flow.Timing{DNSMs: 2, ConnectMs: 5, TLSMs: 10, SendMs: 1, WaitMs: 80, ReceiveMs: 22, TotalMs: 120},
		TLS:         &flow.TLSInfo{Version: "TLS1.3", CipherSuite: "TLS_AES_128_GCM_SHA256", SNI: "api.example.com", Verified: true},
		Note:        "checked",
		StartedAt:   started,
		CompletedAt: &completed,
	}

	har := Build([]*flow.Flow{f}, "1.0-test")
	if har.Log.Version != "1.2" {
		t.Fatalf("version = %s", har.Log.Version)
	}
	if len(har.Log.Entries) != 1 {
		t.Fatalf("entries = %d", len(har.Log.Entries))
	}
	entry := har.Log.Entries[0]
	if entry.Request.URL != "https://api.example.com/v1/orders?q=1" {
		t.Fatalf("url = %s", entry.Request.URL)
	}
	if entry.Response.Status != 201 || entry.Response.Content.Text != `{"id":1}` {
		t.Fatalf("response = %+v", entry.Response)
	}
	if entry.Request.PostData == nil || entry.Request.PostData.Text != `{"sku":"a"}` {
		t.Fatalf("postData = %+v", entry.Request.PostData)
	}
	if entry.Timings.Wait != 80 || entry.Timings.SSL != 10 {
		t.Fatalf("timings = %+v", entry.Timings)
	}
	if entry.ServerIPAddress != "93.184.216.34" || entry.Connection != "127.0.0.1:54321" {
		t.Fatalf("server/connection = %s %s", entry.ServerIPAddress, entry.Connection)
	}

	var buf bytes.Buffer
	if err := Write(&buf, []*flow.Flow{f}, "1.0-test"); err != nil {
		t.Fatal(err)
	}
	var decoded HAR
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("invalid HAR JSON: %v", err)
	}
	if len(decoded.Log.Entries) != 1 {
		t.Fatalf("decoded entries = %d", len(decoded.Log.Entries))
	}
}
