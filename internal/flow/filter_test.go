package flow

import (
	"testing"
	"time"
)

func testFlow() *Flow {
	return &Flow{
		ID:         "f1",
		Seq:        1,
		Scheme:     "https",
		Host:       "api.example.com",
		Port:       443,
		Method:     "POST",
		Path:       "/v1/orders?page=2",
		StatusCode: 500,
		Mime:       "application/json",
		ReqSize:    1200,
		RespSize:   800,
		DurationMs: 900,
		Client:     ClientInfo{IP: "127.0.0.1", Port: 50000, App: "chrome.exe", Origin: "proxy"},
		Server:     ServerInfo{IP: "93.184.216.34", Port: 443},
		State:      StateCompleted,
		Mode:       ModeProxy,
		Tags:       []string{"slow", "error"},
		Request: &Message{Headers: Headers{{Name: "Content-Type", Value: "application/json"}},
			Body: &Body{Preview: `{"name":"demo"}`, Text: true}},
		Response: &Message{Headers: Headers{{Name: "Content-Type", Value: "application/json"}},
			Body: &Body{Preview: `{"message":"upstream timeout"}`, Text: true}},
		StartedAt: time.Now(),
	}
}

func TestCompileFilter(t *testing.T) {
	f := testFlow()

	tests := []struct {
		expr string
		want bool
	}{
		{"", true},
		{"method:POST", true},
		{"method:GET", false},
		{"method:GET,POST", true},
		{"host:*.example.com", true},
		{"host:api.example.com", true},
		{"host:other.dev", false},
		{"path:/v1/orders", true},
		{"status:>=400", true},
		{"status:>=500", true},
		{"status:5xx", true},
		{"status:2xx", false},
		{"mime:application/json", true},
		{"mime:image/*", false},
		{"duration:>500ms", true},
		{"duration:>2s", false},
		{"size:>1kb", true},
		{"size:>1mb", false},
		{"body:\"upstream timeout\"", true},
		{"body:not-found", false},
		{"tag:slow", true},
		{"app:chrome", true},
		{"app:firefox", false},
		{"process:chrome", true},
		{"origin:proxy", true},
		{"origin:pcap", false},
		{"scheme:https", true},
		{"mode:proxy", true},
		{"method:POST and status:>=400", true},
		{"method:GET or status:5xx", true},
		{"not method:GET", true},
		{"not mime:image/*", true},
	}

	for _, tc := range tests {
		t.Run(tc.expr, func(t *testing.T) {
			p, err := CompileFilter(tc.expr)
			if err != nil {
				t.Fatalf("CompileFilter(%q) error: %v", tc.expr, err)
			}
			if got := p(f); got != tc.want {
				t.Fatalf("CompileFilter(%q)(flow) = %v, want %v", tc.expr, got, tc.want)
			}
		})
	}
}

func TestCompileFilterErrors(t *testing.T) {
	for _, expr := range []string{"unknown:x", "status:abc", "size:>abc", "duration:>abc", "(method:GET)"} {
		if _, err := CompileFilter(expr); err == nil {
			t.Fatalf("CompileFilter(%q) 应返回错误", expr)
		}
	}
}
