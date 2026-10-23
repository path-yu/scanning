package capture

import (
	"strings"
	"time"
)

type TCPMeta struct {
	Seq    uint32 `json:"seq"`
	Ack    uint32 `json:"ack"`
	Flags  string `json:"flags"`
	Window uint16 `json:"window"`
	MSS    uint16 `json:"mss,omitempty"`
}

type DNSMeta struct {
	ID       uint16   `json:"id"`
	QR       string   `json:"qr"`
	Question string   `json:"question"`
	QType    string   `json:"qtype"`
	RCode    string   `json:"rcode"`
	Answers  []string `json:"answers,omitempty"`
	CNAMEs   []string `json:"cnames,omitempty"`
	TTL      int      `json:"ttl,omitempty"`
}

type TLSMeta struct {
	RecordType string   `json:"recordType"`
	Version    string   `json:"version"`
	SNI        string   `json:"sni,omitempty"`
	ALPN       []string `json:"alpn,omitempty"`
}

// Packet 是一条原始报文及其解码元数据。
type Packet struct {
	ID         string    `json:"id"`
	SessionID  string    `json:"sessionId"`
	No         int64     `json:"no"`
	Timestamp  time.Time `json:"timestamp"`
	CaptureLen int       `json:"captureLen"`
	OrigLen    int       `json:"origLen"`
	LinkType   int       `json:"-"`

	SrcIP    string `json:"srcIp"`
	DstIP    string `json:"dstIp"`
	SrcPort  int    `json:"srcPort"`
	DstPort  int    `json:"dstPort"`
	Protocol string `json:"protocol"`

	TCP     *TCPMeta `json:"tcp,omitempty"`
	DNS     *DNSMeta `json:"dns,omitempty"`
	TLS     *TLSMeta `json:"tls,omitempty"`
	FlowID  string   `json:"flowId,omitempty"`
	Summary string   `json:"summary"`
	Host    string   `json:"host,omitempty"`

	Payload []byte `json:"payload,omitempty"` // 最多 4KB 预览
	Raw     []byte `json:"-"`                 // 完整捕获字节，用于 PCAP 导出
}

type PacketSummary struct {
	ID         string    `json:"id"`
	SessionID  string    `json:"sessionId"`
	No         int64     `json:"no"`
	Timestamp  time.Time `json:"timestamp"`
	CaptureLen int       `json:"captureLen"`
	OrigLen    int       `json:"origLen"`
	SrcIP      string    `json:"srcIp"`
	DstIP      string    `json:"dstIp"`
	SrcPort    int       `json:"srcPort"`
	DstPort    int       `json:"dstPort"`
	Protocol   string    `json:"protocol"`
	Kind       string    `json:"kind,omitempty"`
	Summary    string    `json:"summary"`
	Host       string    `json:"host,omitempty"`
	FlowID     string    `json:"flowId,omitempty"`
}

func (p *Packet) SummaryInfo() PacketSummary {
	kind := ""
	switch {
	case p.DNS != nil:
		kind = "dns"
	case p.TLS != nil:
		kind = "tls"
	case p.Protocol == "TCP":
		kind = "tcp"
	case p.Protocol == "UDP":
		kind = "udp"
	case strings.HasPrefix(p.Protocol, "ICMP"):
		kind = "icmp"
	default:
		kind = strings.ToLower(p.Protocol)
	}
	return PacketSummary{
		ID:         p.ID,
		SessionID:  p.SessionID,
		No:         p.No,
		Timestamp:  p.Timestamp,
		CaptureLen: p.CaptureLen,
		OrigLen:    p.OrigLen,
		SrcIP:      p.SrcIP,
		DstIP:      p.DstIP,
		SrcPort:    p.SrcPort,
		DstPort:    p.DstPort,
		Protocol:   p.Protocol,
		Kind:       kind,
		Summary:    p.Summary,
		Host:       p.Host,
		FlowID:     p.FlowID,
	}
}

func (p *Packet) Clone() *Packet {
	if p == nil {
		return nil
	}
	out := *p
	if p.TCP != nil {
		v := *p.TCP
		out.TCP = &v
	}
	if p.DNS != nil {
		v := *p.DNS
		v.Answers = append([]string(nil), p.DNS.Answers...)
		v.CNAMEs = append([]string(nil), p.DNS.CNAMEs...)
		out.DNS = &v
	}
	if p.TLS != nil {
		v := *p.TLS
		v.ALPN = append([]string(nil), p.TLS.ALPN...)
		out.TLS = &v
	}
	out.Payload = append([]byte(nil), p.Payload...)
	out.Raw = p.Raw // 原始字节只读共享，避免导出时重复拷贝。
	return &out
}

type InterfaceInfo struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Addresses   []string `json:"addresses"`
	Loopback    bool     `json:"loopback"`
	Default     bool     `json:"default"`
}

type CaptureStatus struct {
	Running     bool     `json:"running"`
	Available   bool     `json:"available"`
	Backend     string   `json:"backend"`
	Reason      string   `json:"reason,omitempty"`
	Interface   string   `json:"interface,omitempty"`
	BPF         string   `json:"bpf,omitempty"`
	Promisc     bool     `json:"promisc"`
	Mirror      bool     `json:"mirror"`
	Packets     int      `json:"packets"`
	Capacity    int      `json:"capacity"`
	Flows       int      `json:"flows"`
	DNS         int      `json:"dns"`
	Dropped     int64    `json:"dropped"`
	Truncated   int64    `json:"truncated"`
	Rate        float64  `json:"rate"`
	UptimeSec   int64    `json:"uptimeSec"`
	Error       string   `json:"error,omitempty"`
	LinkType    int      `json:"linkType"`
	InstallHint []string `json:"installHint,omitempty"`
}

type ImportResult struct {
	Packets int   `json:"packets"`
	Flows   int   `json:"flows"`
	DNS     int   `json:"dns"`
	Bytes   int64 `json:"bytes"`
	Elapsed int64 `json:"elapsedMs"`
}

type DNSEntry struct {
	IP        string    `json:"ip"`
	Domain    string    `json:"domain"`
	TTL       int       `json:"ttl"`
	SeenAt    time.Time `json:"seenAt"`
	ExpiresAt time.Time `json:"expiresAt"`
}
