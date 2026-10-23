package capture

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

var dnsTypeNames = map[uint16]string{
	1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
	16: "TXT", 28: "AAAA", 33: "SRV", 35: "NAPTR", 43: "DS",
	46: "RRSIG", 47: "NSEC", 48: "DNSKEY", 64: "SVCB", 65: "HTTPS",
	255: "ANY",
}

var dnsRCodeNames = map[int]string{
	0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
	4: "NOTIMP", 5: "REFUSED",
}

func parseDNS(msg []byte) *DNSMeta {
	if len(msg) < 12 {
		return nil
	}
	id := binary.BigEndian.Uint16(msg[0:2])
	flags := binary.BigEndian.Uint16(msg[2:4])
	qdCount := int(binary.BigEndian.Uint16(msg[4:6]))
	anCount := int(binary.BigEndian.Uint16(msg[6:8]))

	meta := &DNSMeta{
		ID:    id,
		QR:    map[bool]string{true: "response", false: "query"}[flags&0x8000 != 0],
		RCode: dnsRCodeNames[int(flags&0x0f)],
	}
	if meta.RCode == "" {
		meta.RCode = fmt.Sprintf("RCODE-%d", flags&0x0f)
	}

	offset := 12
	for i := 0; i < qdCount && i < 16; i++ {
		name, next, ok := readDNSName(msg, offset)
		if !ok || next+4 > len(msg) {
			break
		}
		qType := binary.BigEndian.Uint16(msg[next : next+2])
		offset = next + 4
		if i == 0 {
			meta.Question = name
			meta.QType = dnsTypeName(qType)
		}
	}

	answerIPs := make([]string, 0, 4)
	cnames := make([]string, 0, 2)
	for i := 0; i < anCount && i < 64; i++ {
		_, next, ok := readDNSName(msg, offset)
		if !ok || next+10 > len(msg) {
			break
		}
		rType := binary.BigEndian.Uint16(msg[next : next+2])
		ttl := int(binary.BigEndian.Uint32(msg[next+4 : next+8]))
		rdLen := int(binary.BigEndian.Uint16(msg[next+8 : next+10]))
		rdata := next + 10
		if rdata+rdLen > len(msg) {
			break
		}
		switch rType {
		case 1:
			if rdLen == 4 {
				answerIPs = append(answerIPs, net.IP(msg[rdata:rdata+4]).String())
				if ttl > meta.TTL {
					meta.TTL = ttl
				}
			}
		case 28:
			if rdLen == 16 {
				answerIPs = append(answerIPs, net.IP(msg[rdata:rdata+16]).String())
				if ttl > meta.TTL {
					meta.TTL = ttl
				}
			}
		case 5:
			if cname, _, ok := readDNSName(msg, rdata); ok {
				cnames = append(cnames, cname)
			}
		}
		offset = rdata + rdLen
	}
	meta.Answers = answerIPs
	meta.CNAMEs = cnames
	return meta
}

func readDNSName(msg []byte, offset int) (string, int, bool) {
	if offset < 0 || offset >= len(msg) {
		return "", offset, false
	}
	labels := make([]string, 0, 4)
	pos := offset
	next := offset
	jumped := false
	hops := 0
	for {
		if pos < 0 || pos >= len(msg) || hops > 32 {
			return "", next, false
		}
		length := int(msg[pos])
		switch {
		case length == 0:
			pos++
			if !jumped {
				next = pos
			}
			return strings.Join(labels, "."), next, true
		case length&0xc0 == 0xc0:
			if pos+1 >= len(msg) {
				return "", next, false
			}
			if !jumped {
				next = pos + 2
				jumped = true
			}
			pos = ((length & 0x3f) << 8) | int(msg[pos+1])
			hops++
		case length&0xc0 != 0:
			return "", next, false
		default:
			pos++
			if pos+length > len(msg) || length > 63 {
				return "", next, false
			}
			labels = append(labels, string(msg[pos:pos+length]))
			pos += length
			if !jumped {
				next = pos
			}
		}
	}
}

func dnsTypeName(value uint16) string {
	if name, ok := dnsTypeNames[value]; ok {
		return name
	}
	return fmt.Sprintf("TYPE-%d", value)
}
