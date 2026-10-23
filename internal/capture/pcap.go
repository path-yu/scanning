package capture

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"
)

const maxPcapRecord = 64 << 20

type PcapRecord struct {
	Timestamp time.Time
	Data      []byte
	OrigLen   int
	LinkType  int
}

type PcapReader struct {
	r      io.Reader
	order  binary.ByteOrder
	nano   bool
	link   int
	inited bool
}

func NewPcapReader(r io.Reader) *PcapReader {
	return &PcapReader{r: r}
}

func (p *PcapReader) LinkType() int {
	if !p.inited {
		_ = p.readHeader()
	}
	return p.link
}

func (p *PcapReader) Next() (*PcapRecord, error) {
	if !p.inited {
		if err := p.readHeader(); err != nil {
			return nil, err
		}
	}
	header := make([]byte, 16)
	if _, err := io.ReadFull(p.r, header); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, io.EOF
		}
		return nil, err
	}
	sec := p.order.Uint32(header[0:4])
	frac := p.order.Uint32(header[4:8])
	inclLen := int(p.order.Uint32(header[8:12]))
	origLen := int(p.order.Uint32(header[12:16]))
	if inclLen < 0 || inclLen > maxPcapRecord {
		return nil, fmt.Errorf("pcap 记录长度异常: %d", inclLen)
	}
	data := make([]byte, inclLen)
	if _, err := io.ReadFull(p.r, data); err != nil {
		return nil, fmt.Errorf("读取 pcap 记录: %w", err)
	}
	nanos := int64(frac) * 1000
	if p.nano {
		nanos = int64(frac)
	}
	if origLen <= 0 {
		origLen = inclLen
	}
	return &PcapRecord{
		Timestamp: time.Unix(int64(sec), nanos),
		Data:      data,
		OrigLen:   origLen,
		LinkType:  p.link,
	}, nil
}

func (p *PcapReader) readHeader() error {
	header := make([]byte, 24)
	if _, err := io.ReadFull(p.r, header); err != nil {
		return fmt.Errorf("读取 pcap 文件头: %w", err)
	}
	switch {
	case header[0] == 0x0a && header[1] == 0x0d && header[2] == 0x0d && header[3] == 0x0a:
		return errors.New("暂不支持 pcapng 格式，请先用 Wireshark 转换为 pcap")
	case header[0] == 0xd4 && header[1] == 0xc3 && header[2] == 0xb2 && header[3] == 0xa1:
		p.order = binary.LittleEndian
	case header[0] == 0xa1 && header[1] == 0xb2 && header[2] == 0xc3 && header[3] == 0xd4:
		p.order = binary.BigEndian
	case header[0] == 0x4d && header[1] == 0x3c && header[2] == 0xb2 && header[3] == 0xa1:
		p.order = binary.LittleEndian
		p.nano = true
	case header[0] == 0xa1 && header[1] == 0xb2 && header[2] == 0x3c && header[3] == 0x4d:
		p.order = binary.BigEndian
		p.nano = true
	default:
		return fmt.Errorf("不是有效的 pcap 文件（magic=% x）", header[0:4])
	}
	network := p.order.Uint32(header[20:24]) & 0xffff
	p.link = int(network)
	p.inited = true
	return nil
}

type PcapWriter struct {
	w        io.Writer
	linkType int
	nano     bool
}

func NewPcapWriter(w io.Writer, linkType int) (*PcapWriter, error) {
	if linkType <= 0 {
		linkType = LinkTypeEthernet
	}
	writer := &PcapWriter{w: w, linkType: linkType}
	header := make([]byte, 24)
	binary.LittleEndian.PutUint32(header[0:4], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(header[4:6], 2)
	binary.LittleEndian.PutUint16(header[6:8], 4)
	binary.LittleEndian.PutUint32(header[16:20], 65535)
	binary.LittleEndian.PutUint32(header[20:24], uint32(linkType))
	if _, err := w.Write(header); err != nil {
		return nil, err
	}
	return writer, nil
}

func (p *PcapWriter) Write(ts time.Time, data []byte, origLen int) error {
	if origLen <= 0 || origLen < len(data) {
		origLen = len(data)
	}
	header := make([]byte, 16)
	binary.LittleEndian.PutUint32(header[0:4], uint32(ts.Unix()))
	nanos := ts.Nanosecond()
	frac := nanos / 1000
	if p.nano {
		frac = nanos
	}
	binary.LittleEndian.PutUint32(header[4:8], uint32(frac))
	binary.LittleEndian.PutUint32(header[8:12], uint32(len(data)))
	binary.LittleEndian.PutUint32(header[12:16], uint32(origLen))
	if _, err := p.w.Write(header); err != nil {
		return err
	}
	if len(data) > 0 {
		if _, err := p.w.Write(data); err != nil {
			return err
		}
	}
	return nil
}
