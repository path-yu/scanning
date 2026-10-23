package capture

import "fmt"

// parseTLSClientHello 从 TCP 载荷中提取 TLS ClientHello 的 SNI/ALPN。
// 只处理完整的单条握手记录；跨记录/跨段的 ClientHello 由重组后再次尝试。
func parseTLSClientHello(data []byte) *TLSMeta {
	if len(data) < 5 || data[0] != 0x16 {
		return nil
	}
	recordLen := int(data[3])<<8 | int(data[4])
	if recordLen == 0 || len(data) < 5+recordLen {
		return nil
	}
	version := tlsVersionName(data[1], data[2])
	body := data[5 : 5+recordLen]
	if len(body) < 4 || body[0] != 0x01 {
		return nil
	}
	hsLen := int(body[1])<<16 | int(body[2])<<8 | int(body[3])
	if hsLen <= 0 || len(body) < 4+hsLen {
		return nil
	}
	hs := body[4 : 4+hsLen]
	if len(hs) < 34 {
		return nil
	}
	pos := 34 // legacy_version(2) + random(32)
	if pos >= len(hs) {
		return nil
	}
	sessionLen := int(hs[pos])
	pos += 1 + sessionLen
	if pos+2 > len(hs) {
		return nil
	}
	cipherLen := int(hs[pos])<<8 | int(hs[pos+1])
	pos += 2 + cipherLen
	if pos >= len(hs) {
		return nil
	}
	compLen := int(hs[pos])
	pos += 1 + compLen
	meta := &TLSMeta{RecordType: "handshake", Version: version}
	if pos+2 > len(hs) {
		return meta
	}
	extLen := int(hs[pos])<<8 | int(hs[pos+1])
	pos += 2
	end := pos + extLen
	if end > len(hs) {
		end = len(hs)
	}
	for pos+4 <= end {
		extType := int(hs[pos])<<8 | int(hs[pos+1])
		extSize := int(hs[pos+2])<<8 | int(hs[pos+3])
		pos += 4
		if pos+extSize > end {
			break
		}
		ext := hs[pos : pos+extSize]
		switch extType {
		case 0: // server_name
			if len(ext) >= 5 {
				listLen := int(ext[0])<<8 | int(ext[1])
				inner := ext[2:]
				if listLen > len(inner) {
					listLen = len(inner)
				}
				inner = inner[:listLen]
				if len(inner) >= 3 && inner[0] == 0 {
					nameLen := int(inner[1])<<8 | int(inner[2])
					if 3+nameLen <= len(inner) {
						meta.SNI = string(inner[3 : 3+nameLen])
					}
				}
			}
		case 16: // ALPN
			if len(ext) >= 2 {
				listLen := int(ext[0])<<8 | int(ext[1])
				inner := ext[2:]
				if listLen > len(inner) {
					listLen = len(inner)
				}
				inner = inner[:listLen]
				for len(inner) > 0 {
					n := int(inner[0])
					if n == 0 || 1+n > len(inner) {
						break
					}
					meta.ALPN = append(meta.ALPN, string(inner[1:1+n]))
					inner = inner[1+n:]
				}
			}
		}
		pos += extSize
	}
	return meta
}

func tlsVersionName(major, minor byte) string {
	switch {
	case major == 3 && minor == 1:
		return "TLS1.0"
	case major == 3 && minor == 2:
		return "TLS1.1"
	case major == 3 && minor == 3:
		return "TLS1.2"
	case major == 3 && minor == 4:
		return "TLS1.3"
	default:
		return fmt.Sprintf("0x%02x%02x", major, minor)
	}
}
