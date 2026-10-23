package capture

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
)

const (
	LinkTypeNull      = 0
	LinkTypeEthernet  = 1
	LinkTypeRaw       = 101
	LinkTypeLinuxSLL  = 113
	LinkTypeLinuxSLL2 = 276
	LinkTypeLoopback  = 108
)

var errShortPacket = errors.New("报文长度不足")

type Decoded struct {
	SrcIP    string
	DstIP    string
	SrcPort  int
	DstPort  int
	Protocol string

	TCP     *TCPMeta
	DNS     *DNSMeta
	TLS     *TLSMeta
	Payload []byte
}

// Decode 解析链路层到传输层，并按端口/首字节识别 DNS 与 TLS ClientHello。
func Decode(linkType int, data []byte) (*Decoded, error) {
	if len(data) == 0 {
		return nil, errShortPacket
	}
	network, protocolHint, err := stripLinkLayer(linkType, data)
	if err != nil {
		return nil, err
	}
	if network == nil {
		return protocolHint, nil
	}

	var ipVersion int
	var proto uint8
	var payload []byte
	var srcIP, dstIP string
	var fragOffset int

	switch network[0] >> 4 {
	case 4:
		ipVersion = 4
		if len(network) < 20 {
			return nil, errShortPacket
		}
		ihl := int(network[0]&0x0f) * 4
		if ihl < 20 || len(network) < ihl {
			return nil, fmt.Errorf("IPv4 头长度无效: %d", ihl)
		}
		total := int(binary.BigEndian.Uint16(network[2:4]))
		if total == 0 || total > len(network) {
			total = len(network)
		}
		if total < ihl {
			return nil, errShortPacket
		}
		proto = network[9]
		frag := binary.BigEndian.Uint16(network[6:8])
		fragOffset = int(frag & 0x1fff)
		srcIP = net.IP(network[12:16]).String()
		dstIP = net.IP(network[16:20]).String()
		payload = network[ihl:total]
	case 6:
		ipVersion = 6
		if len(network) < 40 {
			return nil, errShortPacket
		}
		payloadLen := int(binary.BigEndian.Uint16(network[4:6]))
		end := 40 + payloadLen
		if payloadLen == 0 || end > len(network) {
			end = len(network)
		}
		next := network[6]
		off := 40
		for {
			switch next {
			case 0, 43, 60: // Hop-by-Hop / Routing / Destination Options
				if off+2 > end {
					return nil, errShortPacket
				}
				next = network[off]
				off += (int(network[off+1]) + 1) * 8
			case 44: // Fragment
				if off+8 > end {
					return nil, errShortPacket
				}
				fragOffset = int(binary.BigEndian.Uint16(network[off+2:off+4]) >> 3)
				next = network[off]
				off += 8
			case 51: // Authentication Header
				if off+2 > end {
					return nil, errShortPacket
				}
				next = network[off]
				off += (int(network[off+1]) + 2) * 4
			case 50: // ESP，内容已加密
				return &Decoded{SrcIP: net.IP(network[8:24]).String(), DstIP: net.IP(network[24:40]).String(), Protocol: "ESP"}, nil
			default:
				goto ipv6Done
			}
			if off < 40 || off > end {
				return nil, errShortPacket
			}
		}
	ipv6Done:
		proto = next
		srcIP = net.IP(network[8:24]).String()
		dstIP = net.IP(network[24:40]).String()
		if off > end {
			return nil, errShortPacket
		}
		payload = network[off:end]
	default:
		return &Decoded{Protocol: "OTHER"}, nil
	}

	out := &Decoded{SrcIP: srcIP, DstIP: dstIP}
	if fragOffset > 0 {
		out.Protocol = protocolName(proto)
		return out, nil
	}

	switch proto {
	case 6:
		out.Protocol = "TCP"
		parseTCP(out, payload)
	case 17:
		out.Protocol = "UDP"
		parseUDP(out, payload)
	case 1:
		out.Protocol = "ICMP"
		out.Payload = payload
	case 58:
		out.Protocol = "ICMPv6"
		out.Payload = payload
	default:
		out.Protocol = protocolName(proto)
		out.Payload = payload
	}

	if out.Protocol == "TCP" && out.Payload != nil && len(out.Payload) > 0 && out.Payload[0] == 0x16 {
		out.TLS = parseTLSClientHello(out.Payload)
	}
	_ = ipVersion
	return out, nil
}

func stripLinkLayer(linkType int, data []byte) ([]byte, *Decoded, error) {
	switch linkType {
	case LinkTypeEthernet:
		if len(data) < 14 {
			return nil, nil, errShortPacket
		}
		etherType := binary.BigEndian.Uint16(data[12:14])
		offset := 14
		for etherType == 0x8100 || etherType == 0x88a8 {
			if len(data) < offset+4 {
				return nil, nil, errShortPacket
			}
			etherType = binary.BigEndian.Uint16(data[offset+2 : offset+4])
			offset += 4
		}
		switch etherType {
		case 0x0800, 0x86dd:
			return data[offset:], nil, nil
		case 0x0806:
			return nil, &Decoded{Protocol: "ARP"}, nil
		default:
			return nil, &Decoded{Protocol: "OTHER"}, nil
		}
	case LinkTypeLinuxSLL:
		if len(data) < 16 {
			return nil, nil, errShortPacket
		}
		etherType := binary.BigEndian.Uint16(data[14:16])
		if etherType == 0x0800 || etherType == 0x86dd {
			return data[16:], nil, nil
		}
		return nil, &Decoded{Protocol: protocolNameEtherType(etherType)}, nil
	case LinkTypeLinuxSLL2:
		if len(data) < 20 {
			return nil, nil, errShortPacket
		}
		etherType := binary.BigEndian.Uint16(data[0:2])
		if etherType == 0x0800 || etherType == 0x86dd {
			return data[20:], nil, nil
		}
		return nil, &Decoded{Protocol: protocolNameEtherType(etherType)}, nil
	case LinkTypeNull, LinkTypeLoopback:
		if len(data) < 4 {
			return nil, nil, errShortPacket
		}
		family := binary.LittleEndian.Uint32(data[0:4])
		if family == 2 || family == 24 || family == 28 || family == 30 {
			return data[4:], nil, nil
		}
		return nil, &Decoded{Protocol: "OTHER"}, nil
	case LinkTypeRaw:
		if data[0]>>4 == 4 || data[0]>>4 == 6 {
			return data, nil, nil
		}
		return nil, &Decoded{Protocol: "OTHER"}, nil
	default:
		// 未知链路类型时尝试按 IP 版本直接解析。
		if data[0]>>4 == 4 || data[0]>>4 == 6 {
			return data, nil, nil
		}
		return nil, &Decoded{Protocol: "OTHER"}, nil
	}
}

func parseTCP(out *Decoded, data []byte) {
	if len(data) < 20 {
		return
	}
	out.SrcPort = int(binary.BigEndian.Uint16(data[0:2]))
	out.DstPort = int(binary.BigEndian.Uint16(data[2:4]))
	tcp := &TCPMeta{
		Seq:    binary.BigEndian.Uint32(data[4:8]),
		Ack:    binary.BigEndian.Uint32(data[8:12]),
		Window: binary.BigEndian.Uint16(data[14:16]),
		Flags:  tcpFlagsName(data[13]),
	}
	dataOffset := int(data[12]>>4) * 4
	if dataOffset < 20 || dataOffset > len(data) {
		dataOffset = 20
	}
	if dataOffset > 20 {
		tcp.MSS = parseMSS(data[20:dataOffset])
	}
	out.TCP = tcp
	out.Payload = data[dataOffset:]
}

func parseUDP(out *Decoded, data []byte) {
	if len(data) < 8 {
		return
	}
	out.SrcPort = int(binary.BigEndian.Uint16(data[0:2]))
	out.DstPort = int(binary.BigEndian.Uint16(data[2:4]))
	length := int(binary.BigEndian.Uint16(data[4:6]))
	if length < 8 || length > len(data) {
		length = len(data)
	}
	payload := data[8:length]
	out.Payload = payload
	if out.SrcPort == 53 || out.DstPort == 53 || out.SrcPort == 5353 || out.DstPort == 5353 {
		out.DNS = parseDNS(payload)
	}
}

func parseMSS(options []byte) uint16 {
	for i := 0; i < len(options); {
		kind := options[i]
		if kind == 0 {
			break
		}
		if kind == 1 {
			i++
			continue
		}
		if i+1 >= len(options) {
			break
		}
		length := int(options[i+1])
		if length < 2 || i+length > len(options) {
			break
		}
		if kind == 2 && length == 4 {
			return binary.BigEndian.Uint16(options[i+2 : i+4])
		}
		i += length
	}
	return 0
}

func tcpFlagsName(flags byte) string {
	names := make([]string, 0, 5)
	if flags&0x02 != 0 {
		names = append(names, "SYN")
	}
	if flags&0x01 != 0 {
		names = append(names, "FIN")
	}
	if flags&0x04 != 0 {
		names = append(names, "RST")
	}
	if flags&0x08 != 0 {
		names = append(names, "PSH")
	}
	if flags&0x10 != 0 {
		names = append(names, "ACK")
	}
	if flags&0x20 != 0 {
		names = append(names, "URG")
	}
	if len(names) == 0 {
		return "-"
	}
	return strings.Join(names, ",")
}

func protocolName(proto uint8) string {
	switch proto {
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 1:
		return "ICMP"
	case 58:
		return "ICMPv6"
	case 50:
		return "ESP"
	case 51:
		return "AH"
	default:
		return fmt.Sprintf("IP-%d", proto)
	}
}

func protocolNameEtherType(etherType uint16) string {
	switch etherType {
	case 0x0806:
		return "ARP"
	case 0x86dd:
		return "IPv6"
	case 0x0800:
		return "IPv4"
	default:
		return fmt.Sprintf("ETH-0x%04x", etherType)
	}
}
