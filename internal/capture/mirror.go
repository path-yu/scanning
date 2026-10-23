package capture

import (
	"bytes"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"scanning/internal/flow"
)

const mirrorBodyLimit = 64 << 10
const mirrorChunkSize = 1400

// MirrorFlow 将完成后的代理 Flow 转换为合成 TCP 报文，用于无驱动环境的报文视图与 PCAP 导出。
func (e *Engine) MirrorFlow(f *flow.Flow) {
	if f == nil || f.Mode != flow.ModeProxy || !e.MirrorEnabled() {
		return
	}
	if net.ParseIP(f.Server.IP).To4() == nil || net.ParseIP(f.Client.IP).To4() == nil {
		return
	}
	clientPort := f.Client.Port
	if clientPort <= 0 {
		clientPort = 49152
	}
	serverPort := f.Port
	if serverPort <= 0 {
		serverPort = 80
	}
	reqBytes := buildMirrorRequest(f, e.bodyBytes(f.Request))
	respBytes := buildMirrorResponse(f, e.bodyBytes(f.Response))
	if len(reqBytes) == 0 {
		return
	}

	started := f.StartedAt
	if started.IsZero() {
		started = time.Now()
	}
	completed := started.Add(2 * time.Millisecond)
	if f.CompletedAt != nil && f.CompletedAt.After(started) {
		completed = *f.CompletedAt
	}
	client := f.Client.IP
	server := f.Server.IP
	clientSeq := uint32(1000)
	serverSeq := uint32(5000)
	flowID := f.ID
	host := f.Host

	send := func(src, dst string, sport, dport int, seq, ack uint32, flags uint8, payload []byte, ts time.Time, summary string) {
		frame := buildTCPFrame(src, dst, sport, dport, seq, ack, flags, payload)
		dec, err := Decode(LinkTypeEthernet, frame)
		if err != nil {
			return
		}
		p := &Packet{
			Timestamp:  ts,
			CaptureLen: len(frame),
			OrigLen:    len(frame),
			LinkType:   LinkTypeEthernet,
			SrcIP:      dec.SrcIP,
			DstIP:      dec.DstIP,
			SrcPort:    dec.SrcPort,
			DstPort:    dec.DstPort,
			Protocol:   dec.Protocol,
			TCP:        dec.TCP,
			FlowID:     flowID,
			Host:       host,
			Summary:    summary,
			Raw:        frame,
		}
		if len(payload) > 0 {
			preview := payload
			if len(preview) > 4096 {
				preview = preview[:4096]
			}
			p.Payload = append([]byte(nil), preview...)
		}
		e.packets.Add(p)
		e.packetCount.Add(1)
		e.bytes.Add(int64(len(frame)))
		e.mirrored.Add(1)
	}

	handshakeAt := started
	send(client, server, clientPort, serverPort, clientSeq, 0, 0x02, nil, handshakeAt, "TCP SYN")
	clientSeq++
	send(server, client, serverPort, clientPort, serverSeq, clientSeq, 0x12, nil, handshakeAt.Add(200*time.Microsecond), "TCP SYN,ACK")
	serverSeq++
	send(client, server, clientPort, serverPort, clientSeq, serverSeq, 0x10, nil, handshakeAt.Add(400*time.Microsecond), "TCP ACK")

	requestAt := handshakeAt.Add(time.Millisecond)
	chunks := splitChunks(reqBytes, mirrorChunkSize)
	for i, chunk := range chunks {
		summary := fmt.Sprintf("HTTP 请求 · %s %s", f.Method, f.Path)
		if i > 0 {
			summary = "HTTP 请求正文"
		}
		send(client, server, clientPort, serverPort, clientSeq, serverSeq, 0x18, chunk, requestAt, summary)
		clientSeq += uint32(len(chunk))
	}
	send(server, client, serverPort, clientPort, serverSeq, clientSeq, 0x10, nil, requestAt, "TCP ACK")

	responseAt := completed
	if responseAt.Before(requestAt) {
		responseAt = requestAt.Add(time.Millisecond)
	}
	respChunks := splitChunks(respBytes, mirrorChunkSize)
	for i, chunk := range respChunks {
		summary := fmt.Sprintf("HTTP 响应 · %d %s", f.StatusCode, http.StatusText(f.StatusCode))
		if i > 0 {
			summary = "HTTP 响应正文"
		}
		send(server, client, serverPort, clientPort, serverSeq, clientSeq, 0x18, chunk, responseAt, summary)
		serverSeq += uint32(len(chunk))
	}
	send(client, server, clientPort, serverPort, clientSeq, serverSeq, 0x10, nil, responseAt.Add(time.Millisecond), "TCP ACK")
	finAt := responseAt.Add(2 * time.Millisecond)
	send(client, server, clientPort, serverPort, clientSeq, serverSeq, 0x11, nil, finAt, "TCP FIN,ACK")
	clientSeq++
	send(server, client, serverPort, clientPort, serverSeq, clientSeq, 0x11, nil, finAt.Add(time.Millisecond), "TCP FIN,ACK")
	slog.Debug("代理镜像已生成报文", "flow", f.ID, "packets", len(chunks)+len(respChunks)+7)
}

func (e *Engine) bodyBytes(msg *flow.Message) []byte {
	if msg == nil || msg.Body == nil {
		return nil
	}
	body := msg.Body
	var data []byte
	if body.Ref != "" && e.deps.Blobs != nil {
		if stored, err := e.deps.Blobs.Get(body.Ref); err == nil {
			data = stored
		}
	}
	if data == nil && body.Text {
		data = []byte(body.Preview)
	}
	if len(data) > mirrorBodyLimit {
		data = data[:mirrorBodyLimit]
	}
	return data
}

func buildMirrorRequest(f *flow.Flow, body []byte) []byte {
	var buf bytes.Buffer
	path := f.Path
	if path == "" {
		path = "/"
	}
	method := f.Method
	if method == "" {
		method = http.MethodGet
	}
	fmt.Fprintf(&buf, "%s %s HTTP/1.1\r\n", method, path)
	if f.Request != nil {
		writeMirrorHeaders(&buf, f.Request.Headers, f.Host, len(body))
	} else {
		fmt.Fprintf(&buf, "Host: %s\r\n", f.Host)
		if len(body) > 0 {
			fmt.Fprintf(&buf, "Content-Length: %d\r\n", len(body))
		}
	}
	buf.WriteString("\r\n")
	buf.Write(body)
	return buf.Bytes()
}

func buildMirrorResponse(f *flow.Flow, body []byte) []byte {
	var buf bytes.Buffer
	status := f.StatusCode
	if status == 0 {
		status = http.StatusOK
	}
	fmt.Fprintf(&buf, "HTTP/1.1 %d %s\r\n", status, http.StatusText(status))
	if f.Response != nil {
		writeMirrorHeaders(&buf, f.Response.Headers, "", len(body))
	} else if len(body) > 0 {
		fmt.Fprintf(&buf, "Content-Length: %d\r\n", len(body))
	}
	buf.WriteString("\r\n")
	buf.Write(body)
	return buf.Bytes()
}

func writeMirrorHeaders(buf *bytes.Buffer, headers flow.Headers, host string, bodyLen int) {
	wroteHost := false
	for _, header := range headers {
		name := header.Name
		lower := strings.ToLower(name)
		switch lower {
		case "host":
			if host != "" {
				if !wroteHost {
					fmt.Fprintf(buf, "Host: %s\r\n", host)
					wroteHost = true
				}
			} else {
				fmt.Fprintf(buf, "%s: %s\r\n", name, header.Value)
			}
		case "content-length", "transfer-encoding", "connection", "proxy-connection":
			continue
		default:
			fmt.Fprintf(buf, "%s: %s\r\n", name, header.Value)
		}
	}
	if host != "" && !wroteHost {
		fmt.Fprintf(buf, "Host: %s\r\n", host)
	}
	if bodyLen > 0 {
		fmt.Fprintf(buf, "Content-Length: %d\r\n", bodyLen)
	}
}

func splitChunks(data []byte, size int) [][]byte {
	if len(data) == 0 {
		return nil
	}
	out := make([][]byte, 0, (len(data)+size-1)/size)
	for len(data) > 0 {
		n := size
		if n > len(data) {
			n = len(data)
		}
		out = append(out, data[:n])
		data = data[n:]
	}
	return out
}

var mirrorPacketID atomic.Uint32

func buildTCPFrame(srcIP, dstIP string, sport, dport int, seq, ack uint32, flags uint8, payload []byte) []byte {
	src := net.ParseIP(srcIP).To4()
	dst := net.ParseIP(dstIP).To4()
	if src == nil || dst == nil {
		return nil
	}
	frame := make([]byte, 14+20+20+len(payload))
	copy(frame[0:6], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02})
	copy(frame[6:12], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01})
	frame[12], frame[13] = 0x08, 0x00

	ip := frame[14 : 14+20]
	ip[0] = 0x45
	ip[1] = 0
	total := 20 + 20 + len(payload)
	ip[2] = byte(total >> 8)
	ip[3] = byte(total)
	id := uint16(mirrorPacketID.Add(1))
	ip[4] = byte(id >> 8)
	ip[5] = byte(id)
	ip[6], ip[7] = 0x40, 0x00
	ip[8] = 64
	ip[9] = 6
	copy(ip[12:16], src)
	copy(ip[16:20], dst)
	binaryChecksum := checksum(ip)
	ip[10] = byte(binaryChecksum >> 8)
	ip[11] = byte(binaryChecksum)

	tcp := frame[34:]
	tcp[0] = byte(sport >> 8)
	tcp[1] = byte(sport)
	tcp[2] = byte(dport >> 8)
	tcp[3] = byte(dport)
	putUint32(tcp[4:8], seq)
	putUint32(tcp[8:12], ack)
	tcp[12] = 5 << 4
	tcp[13] = flags
	tcp[14] = 0xff
	tcp[15] = 0xff
	copy(tcp[20:], payload)

	pseudo := make([]byte, 12+20+len(payload))
	copy(pseudo[0:4], src)
	copy(pseudo[4:8], dst)
	pseudo[8] = 0
	pseudo[9] = 6
	tcpLen := 20 + len(payload)
	pseudo[10] = byte(tcpLen >> 8)
	pseudo[11] = byte(tcpLen)
	copy(pseudo[12:], tcp)
	tcpChecksum := checksum(pseudo)
	tcp[16] = byte(tcpChecksum >> 8)
	tcp[17] = byte(tcpChecksum)
	return frame
}

func putUint32(b []byte, value uint32) {
	b[0] = byte(value >> 24)
	b[1] = byte(value >> 16)
	b[2] = byte(value >> 8)
	b[3] = byte(value)
}

func checksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum>>16 > 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
