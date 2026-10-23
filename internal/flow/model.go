package flow

import (
	"net"
	"strconv"
	"strings"
	"time"
)

type Mode string

const (
	ModeProxy Mode = "proxy"
	ModePCAP  Mode = "pcap"
	ModeMixed Mode = "mixed"
)

type State string

const (
	StatePending   State = "pending"
	StateActive    State = "active"
	StatePaused    State = "paused"
	StateCompleted State = "completed"
	StateFailed    State = "failed"
	StateCanceled  State = "canceled"
	StateAborted   State = "aborted"
)

type Flow struct {
	ID        string `json:"id"`
	SessionID string `json:"sessionId"`
	Seq       int64  `json:"seq"`
	Mode      Mode   `json:"mode"`
	State     State  `json:"state"`

	Scheme     string `json:"scheme"`
	Host       string `json:"host"`
	Port       int    `json:"port"`
	Method     string `json:"method"`
	Path       string `json:"path"`
	StatusCode int    `json:"statusCode"`
	Mime       string `json:"mime"`
	ReqSize    int64  `json:"reqSize"`
	RespSize   int64  `json:"respSize"`
	DurationMs int64  `json:"durationMs"`

	Client   ClientInfo `json:"client"`
	Server   ServerInfo `json:"server"`
	Request  *Message   `json:"request,omitempty"`
	Response *Message   `json:"response,omitempty"`
	Timing   *Timing    `json:"timing,omitempty"`
	TLS      *TLSInfo   `json:"tls,omitempty"`

	Error        *FlowError `json:"error,omitempty"`
	Tags         []string   `json:"tags"`
	Note         string     `json:"note"`
	Pinned       bool       `json:"pinned"`
	ReplayedFrom string     `json:"replayedFrom,omitempty"`
	MatchedRules []string   `json:"matchedRules,omitempty"`
	Breakpoint   bool       `json:"breakpoint,omitempty"`

	StartedAt   time.Time  `json:"startedAt"`
	CompletedAt *time.Time `json:"completedAt,omitempty"`
}

type ClientInfo struct {
	IP      string `json:"ip"`
	Port    int    `json:"port"`
	App     string `json:"app,omitempty"`
	PID     int    `json:"pid,omitempty"`
	AppPath string `json:"appPath,omitempty"`
	Origin  string `json:"origin,omitempty"` // proxy | pcap | replay | demo
}

type ServerInfo struct {
	IP   string `json:"ip"`
	Port int    `json:"port"`
	Name string `json:"name,omitempty"`
}

type FlowError struct {
	Stage   string `json:"stage"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type Headers []Header

func (h Headers) Get(name string) string {
	for _, item := range h {
		if strings.EqualFold(item.Name, name) {
			return item.Value
		}
	}
	return ""
}

func (h Headers) Set(name, value string) Headers {
	for i := range h {
		if strings.EqualFold(h[i].Name, name) {
			h[i].Value = value
			return h
		}
	}
	return append(h, Header{Name: name, Value: value})
}

type Message struct {
	HTTPVersion string  `json:"httpVersion"`
	Headers     Headers `json:"headers"`
	Trailers    Headers `json:"trailers,omitempty"`
	Body        *Body   `json:"body,omitempty"`
}

type Body struct {
	Ref          string `json:"ref"`
	Size         int64  `json:"size"`
	CapturedSize int64  `json:"capturedSize"`
	Truncated    bool   `json:"truncated"`
	Mime         string `json:"mime"`
	Encoding     string `json:"encoding"`
	Text         bool   `json:"text"`
	Preview      string `json:"preview,omitempty"`
	Decrypted    bool   `json:"decrypted,omitempty"`
	DecodedMime  string `json:"decodedMime,omitempty"`
}

type Timing struct {
	DNSMs     int64 `json:"dnsMs"`
	ConnectMs int64 `json:"connectMs"`
	TLSMs     int64 `json:"tlsMs"`
	SendMs    int64 `json:"sendMs"`
	WaitMs    int64 `json:"waitMs"`
	ReceiveMs int64 `json:"receiveMs"`
	TotalMs   int64 `json:"totalMs"`
}

type TLSInfo struct {
	Version     string       `json:"version"`
	CipherSuite string       `json:"cipherSuite"`
	SNI         string       `json:"sni"`
	ALPN        string       `json:"alpn"`
	Verified    bool         `json:"verified"`
	Cert        *Certificate `json:"cert,omitempty"`
}

type Certificate struct {
	Subject   string   `json:"subject"`
	Issuer    string   `json:"issuer"`
	NotBefore string   `json:"notBefore"`
	NotAfter  string   `json:"notAfter"`
	SANs      []string `json:"sans"`
}

type Session struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Mode       Mode       `json:"mode"`
	Filter     string     `json:"filter"`
	CreatedAt  time.Time  `json:"createdAt"`
	EndedAt    *time.Time `json:"endedAt,omitempty"`
	FlowCount  int64      `json:"flowCount"`
	ByteCount  int64      `json:"byteCount"`
	Persistent bool       `json:"persistent"`
}

type Summary struct {
	ID           string     `json:"id"`
	SessionID    string     `json:"sessionId"`
	Seq          int64      `json:"seq"`
	Mode         Mode       `json:"mode"`
	State        State      `json:"state"`
	Scheme       string     `json:"scheme"`
	Host         string     `json:"host"`
	Port         int        `json:"port"`
	Method       string     `json:"method"`
	Path         string     `json:"path"`
	StatusCode   int        `json:"statusCode"`
	Mime         string     `json:"mime"`
	ReqSize      int64      `json:"reqSize"`
	RespSize     int64      `json:"respSize"`
	DurationMs   int64      `json:"durationMs"`
	Client       ClientInfo `json:"client"`
	TLS          *TLSInfo   `json:"tls,omitempty"`
	Tags         []string   `json:"tags"`
	Pinned       bool       `json:"pinned"`
	StartedAt    time.Time  `json:"startedAt"`
	MatchedRules []string   `json:"matchedRules,omitempty"`
	Breakpoint   bool       `json:"breakpoint,omitempty"`
}

type Patch struct {
	Note   *string   `json:"note"`
	Tags   *[]string `json:"tags"`
	Pinned *bool     `json:"pinned"`
}

func (f *Flow) Summary() Summary {
	return Summary{
		ID:           f.ID,
		SessionID:    f.SessionID,
		Seq:          f.Seq,
		Mode:         f.Mode,
		State:        f.State,
		Scheme:       f.Scheme,
		Host:         f.Host,
		Port:         f.Port,
		Method:       f.Method,
		Path:         f.Path,
		StatusCode:   f.StatusCode,
		Mime:         f.Mime,
		ReqSize:      f.ReqSize,
		RespSize:     f.RespSize,
		DurationMs:   f.DurationMs,
		Client:       f.Client,
		TLS:          f.TLS,
		Tags:         cloneStrings(f.Tags),
		Pinned:       f.Pinned,
		StartedAt:    f.StartedAt,
		MatchedRules: cloneStrings(f.MatchedRules),
		Breakpoint:   f.Breakpoint,
	}
}

func (f *Flow) URL() string {
	scheme := f.Scheme
	if scheme == "" {
		scheme = "http"
	}
	host := f.Host
	if !isDefaultPort(scheme, f.Port) && f.Port > 0 {
		host = net.JoinHostPort(f.Host, strconv.Itoa(f.Port))
	}
	return scheme + "://" + host + f.Path
}

func isDefaultPort(scheme string, port int) bool {
	return (scheme == "http" && port == 80) ||
		(scheme == "https" && port == 443) ||
		(scheme == "ws" && port == 80) ||
		(scheme == "wss" && port == 443) ||
		(port == 0)
}

// Clone 返回深拷贝，避免读接口与写入方竞争。
func (f *Flow) Clone() *Flow {
	if f == nil {
		return nil
	}
	out := *f
	out.Tags = cloneStrings(f.Tags)
	out.MatchedRules = cloneStrings(f.MatchedRules)
	out.Request = f.Request.Clone()
	out.Response = f.Response.Clone()
	if f.Timing != nil {
		t := *f.Timing
		out.Timing = &t
	}
	if f.TLS != nil {
		t := *f.TLS
		if f.TLS.Cert != nil {
			c := *f.TLS.Cert
			c.SANs = append([]string(nil), f.TLS.Cert.SANs...)
			t.Cert = &c
		}
		out.TLS = &t
	}
	if f.Error != nil {
		e := *f.Error
		out.Error = &e
	}
	if f.CompletedAt != nil {
		t := *f.CompletedAt
		out.CompletedAt = &t
	}
	return &out
}

func (m *Message) Clone() *Message {
	if m == nil {
		return nil
	}
	out := *m
	out.Headers = cloneHeaders(m.Headers)
	out.Trailers = cloneHeaders(m.Trailers)
	if m.Body != nil {
		b := *m.Body
		out.Body = &b
	}
	return &out
}

func cloneHeaders(in Headers) Headers {
	if in == nil {
		return nil
	}
	out := make(Headers, len(in))
	copy(out, in)
	return out
}

// cloneStrings 始终返回非 nil 切片，保证 JSON 输出为 [] 而不是 null。
func cloneStrings(in []string) []string {
	out := make([]string, len(in))
	copy(out, in)
	return out
}
