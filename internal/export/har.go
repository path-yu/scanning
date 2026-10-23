package export

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"scanning/internal/flow"
)

type HAR struct {
	Log Log `json:"log"`
}

type Log struct {
	Version string  `json:"version"`
	Creator Creator `json:"creator"`
	Pages   []Page  `json:"pages"`
	Entries []Entry `json:"entries"`
}

type Creator struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Page struct {
	StartedDateTime string      `json:"startedDateTime"`
	ID              string      `json:"id"`
	Title           string      `json:"title"`
	PageTimings     PageTimings `json:"pageTimings"`
}

type PageTimings struct {
	OnContentLoad float64 `json:"onContentLoad"`
	OnLoad        float64 `json:"onLoad"`
}

type Entry struct {
	StartedDateTime string    `json:"startedDateTime"`
	Time            float64   `json:"time"`
	Request         Request   `json:"request"`
	Response        Response  `json:"response"`
	Cache           struct{}  `json:"cache"`
	Timings         Timings   `json:"timings"`
	ServerIPAddress string    `json:"serverIPAddress,omitempty"`
	Connection      string    `json:"connection,omitempty"`
	Comment         string    `json:"comment,omitempty"`
	Scanning        *Scanning `json:"_scanning,omitempty"`
}

type Request struct {
	Method      string      `json:"method"`
	URL         string      `json:"url"`
	HTTPVersion string      `json:"httpVersion"`
	Cookies     []Cookie    `json:"cookies"`
	Headers     []NameValue `json:"headers"`
	QueryString []NameValue `json:"queryString"`
	PostData    *PostData   `json:"postData,omitempty"`
	HeadersSize int         `json:"headersSize"`
	BodySize    int64       `json:"bodySize"`
}

type Response struct {
	Status      int         `json:"status"`
	StatusText  string      `json:"statusText"`
	HTTPVersion string      `json:"httpVersion"`
	Cookies     []Cookie    `json:"cookies"`
	Headers     []NameValue `json:"headers"`
	Content     Content     `json:"content"`
	RedirectURL string      `json:"redirectURL"`
	HeadersSize int         `json:"headersSize"`
	BodySize    int64       `json:"bodySize"`
}

type Content struct {
	Size     int64  `json:"size"`
	MimeType string `json:"mimeType"`
	Text     string `json:"text,omitempty"`
	Encoding string `json:"encoding,omitempty"`
}

type Cookie struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Path     string `json:"path,omitempty"`
	Domain   string `json:"domain,omitempty"`
	HTTPOnly bool   `json:"httpOnly,omitempty"`
	Secure   bool   `json:"secure,omitempty"`
}

type NameValue struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type PostData struct {
	MimeType string `json:"mimeType"`
	Text     string `json:"text"`
}

type Timings struct {
	Blocked float64 `json:"blocked"`
	DNS     float64 `json:"dns"`
	Connect float64 `json:"connect"`
	Send    float64 `json:"send"`
	Wait    float64 `json:"wait"`
	Receive float64 `json:"receive"`
	SSL     float64 `json:"ssl"`
}

type Scanning struct {
	FlowID       string        `json:"flowId"`
	Mode         flow.Mode     `json:"mode"`
	ClientApp    string        `json:"clientApp,omitempty"`
	ClientPID    int           `json:"clientPid,omitempty"`
	ClientPath   string        `json:"clientPath,omitempty"`
	Origin       string        `json:"origin,omitempty"`
	TLS          *flow.TLSInfo `json:"tls,omitempty"`
	Truncated    bool          `json:"truncated,omitempty"`
	ReplayedFrom string        `json:"replayedFrom,omitempty"`
}

// BodyLoader 读取完整正文；返回 nil 时回退到预览。
type BodyLoader func(body *flow.Body) []byte

func Build(flows []*flow.Flow, version string) HAR {
	return BuildWithBodies(flows, version, nil)
}

func BuildWithBodies(flows []*flow.Flow, version string, loader BodyLoader) HAR {
	entries := make([]Entry, 0, len(flows))
	for _, f := range flows {
		entries = append(entries, buildEntry(f, loader))
	}
	return HAR{Log: Log{
		Version: "1.2",
		Creator: Creator{Name: "Scanning", Version: version},
		Pages:   []Page{},
		Entries: entries,
	}}
}

func Write(w io.Writer, flows []*flow.Flow, version string) error {
	return WriteWithBodies(w, flows, version, nil)
}

func WriteWithBodies(w io.Writer, flows []*flow.Flow, version string, loader BodyLoader) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(BuildWithBodies(flows, version, loader))
}

func buildEntry(f *flow.Flow, loader BodyLoader) Entry {
	req := f.Request
	resp := f.Response

	entry := Entry{
		StartedDateTime: f.StartedAt.Format(time.RFC3339),
		Time:            float64(f.DurationMs),
		Request: Request{
			Method:      f.Method,
			URL:         f.URL(),
			HTTPVersion: "HTTP/1.1",
			HeadersSize: -1,
			BodySize:    f.ReqSize,
			Cookies:     []Cookie{},
			QueryString: queryString(f),
		},
		Response: Response{
			Status:      f.StatusCode,
			StatusText:  http.StatusText(f.StatusCode),
			HTTPVersion: "HTTP/1.1",
			HeadersSize: -1,
			BodySize:    f.RespSize,
			Cookies:     []Cookie{},
			Content: Content{
				Size:     f.RespSize,
				MimeType: f.Mime,
			},
		},
		Cache:   struct{}{},
		Timings: harTimings(f),
		Comment: f.Note,
		Scanning: &Scanning{
			FlowID:       f.ID,
			Mode:         f.Mode,
			ClientApp:    f.Client.App,
			ClientPID:    f.Client.PID,
			ClientPath:   f.Client.AppPath,
			Origin:       f.Client.Origin,
			TLS:          f.TLS,
			ReplayedFrom: f.ReplayedFrom,
		},
	}
	if resp != nil {
		entry.Response.HTTPVersion = resp.HTTPVersion
		entry.Response.Headers = harHeaders(resp.Headers)
		entry.Response.Content.MimeType = firstNonEmpty(f.Mime, headerValue(resp.Headers, "Content-Type"))
		if resp.Body != nil {
			entry.Response.Content.Size = resp.Body.Size
			entry.Response.BodySize = resp.Body.Size
			if resp.Body.Text {
				entry.Response.Content.Text = bodyText(resp.Body, loader)
			}
			entry.Scanning.Truncated = resp.Body.Truncated
		}
		entry.Response.RedirectURL = headerValue(resp.Headers, "Location")
	}
	if req != nil {
		entry.Request.HTTPVersion = req.HTTPVersion
		entry.Request.Headers = harHeaders(req.Headers)
		if req.Body != nil && (req.Body.Text || req.Body.Preview != "") {
			entry.Request.PostData = &PostData{
				MimeType: firstNonEmpty(req.Body.Mime, headerValue(req.Headers, "Content-Type")),
				Text:     bodyText(req.Body, loader),
			}
			entry.Scanning.Truncated = entry.Scanning.Truncated || req.Body.Truncated
		}
	}
	if f.Server.IP != "" {
		entry.ServerIPAddress = f.Server.IP
	}
	if f.Client.IP != "" {
		entry.Connection = f.Client.IP + ":" + strconv.Itoa(f.Client.Port)
	}
	return entry
}

// bodyText 优先读取完整 Blob 正文，失败时回退到内存预览。
func bodyText(body *flow.Body, loader BodyLoader) string {
	if loader != nil {
		if data := loader(body); len(data) > 0 {
			return string(data)
		}
	}
	return body.Preview
}

func harHeaders(headers flow.Headers) []NameValue {
	out := make([]NameValue, 0, len(headers))
	for _, header := range headers {
		out = append(out, NameValue{Name: header.Name, Value: header.Value})
	}
	return out
}

func queryString(f *flow.Flow) []NameValue {
	u, err := url.Parse(f.URL())
	if err != nil {
		return []NameValue{}
	}
	values := u.Query()
	out := make([]NameValue, 0, len(values))
	for name, items := range values {
		for _, item := range items {
			out = append(out, NameValue{Name: name, Value: item})
		}
	}
	return out
}

func harTimings(f *flow.Flow) Timings {
	if f.Timing == nil {
		return Timings{Blocked: -1, DNS: -1, Connect: -1, SSL: -1}
	}
	t := f.Timing
	ssl := float64(-1)
	if f.TLS != nil {
		ssl = float64(t.TLSMs)
	}
	return Timings{
		Blocked: -1,
		DNS:     float64(t.DNSMs),
		Connect: float64(t.ConnectMs),
		Send:    float64(t.SendMs),
		Wait:    float64(t.WaitMs),
		Receive: float64(t.ReceiveMs),
		SSL:     ssl,
	}
}

func headerValue(headers flow.Headers, name string) string {
	return headers.Get(name)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
