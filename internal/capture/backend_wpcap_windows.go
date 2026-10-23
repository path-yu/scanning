//go:build windows && wpcap

package capture

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

const (
	pcapErrBufSize = 256
	pcapIfLoopback = 0x00000001
)

var (
	wpcapOnce sync.Once
	wpcapDLL  *syscall.DLL
	wpcapErr  error
)

func loadWpcap() error {
	wpcapOnce.Do(func() {
		systemRoot := os.Getenv("SystemRoot")
		candidates := []string{
			filepath.Join(systemRoot, "System32", "Npcap", "wpcap.dll"),
			filepath.Join(systemRoot, "System32", "wpcap.dll"),
			"wpcap.dll",
		}
		for _, candidate := range candidates {
			dll, err := syscall.LoadDLL(candidate)
			if err == nil {
				wpcapDLL = dll
				return
			}
		}
		wpcapErr = errors.New("未检测到 Npcap（wpcap.dll），请安装 Npcap 并勾选 WinPcap 兼容模式")
	})
	return wpcapErr
}

func wpcapProc(name string) (*syscall.Proc, error) {
	if err := loadWpcap(); err != nil {
		return nil, err
	}
	proc, err := wpcapDLL.FindProc(name)
	if err != nil {
		return nil, fmt.Errorf("wpcap 函数 %s 不可用: %w", name, err)
	}
	return proc, nil
}

type pcapIf struct {
	Next        *pcapIf
	Name        *byte
	Description *byte
	Addresses   *pcapAddr
	Flags       uint32
}

type pcapAddr struct {
	Next      *pcapAddr
	Addr      *syscall.RawSockaddrAny
	Netmask   *syscall.RawSockaddrAny
	Broadaddr *syscall.RawSockaddrAny
	Dstaddr   *syscall.RawSockaddrAny
}

type pcapPkthdr struct {
	Sec    int32
	Usec   int32
	Caplen uint32
	Len    uint32
}

type bpfProgram struct {
	Len   uint32
	_     uint32
	Insns unsafe.Pointer
}

type wpcapBackend struct{}

func newBackend() Backend { return wpcapBackend{} }

func (wpcapBackend) Name() string { return "Npcap" }

func (wpcapBackend) Available() (bool, string) {
	if err := loadWpcap(); err != nil {
		return false, err.Error()
	}
	return true, ""
}

func (wpcapBackend) InstallHint() []string {
	return []string{
		"安装 Npcap 1.x（勾选 WinPcap 兼容模式）：https://npcap.com/#download",
		"使用管理员权限运行终端后再启动采集",
		"也可以使用「导入 PCAP」或「代理镜像」作为无驱动替代方案",
	}
}

func (wpcapBackend) Interfaces() ([]InterfaceInfo, error) {
	find, err := wpcapProc("pcap_findalldevs")
	if err != nil {
		return nil, err
	}
	free, err := wpcapProc("pcap_freealldevs")
	if err != nil {
		return nil, err
	}
	var devices *pcapIf
	errbuf := make([]byte, pcapErrBufSize)
	ret, _, _ := find.Call(uintptr(unsafe.Pointer(&devices)), uintptr(unsafe.Pointer(&errbuf[0])))
	if int32(ret) != 0 {
		return nil, errors.New(cStringBytes(errbuf))
	}
	if devices == nil {
		return []InterfaceInfo{}, nil
	}
	defer free.Call(uintptr(unsafe.Pointer(devices)))

	out := make([]InterfaceInfo, 0, 8)
	defaultAssigned := false
	for item := devices; item != nil; item = item.Next {
		info := InterfaceInfo{
			Name:        cString(item.Name),
			Description: cString(item.Description),
			Loopback:    item.Flags&pcapIfLoopback != 0,
		}
		if info.Description == "" {
			info.Description = info.Name
		}
		for addr := item.Addresses; addr != nil; addr = addr.Next {
			if ip := sockaddrIP(addr.Addr); ip != "" {
				info.Addresses = append(info.Addresses, ip)
			}
		}
		if !info.Loopback && !defaultAssigned && len(info.Addresses) > 0 {
			info.Default = true
			defaultAssigned = true
		}
		out = append(out, info)
	}
	return out, nil
}

func (wpcapBackend) Open(iface, bpf string, promisc bool) (Source, error) {
	open, err := wpcapProc("pcap_open_live")
	if err != nil {
		return nil, err
	}
	if iface == "" {
		items, err := (wpcapBackend{}).Interfaces()
		if err != nil {
			return nil, err
		}
		for _, item := range items {
			if item.Default {
				iface = item.Name
				break
			}
		}
		if iface == "" && len(items) > 0 {
			iface = items[0].Name
		}
	}
	if iface == "" {
		return nil, errors.New("没有可用的 Npcap 网卡")
	}
	name := append([]byte(iface), 0)
	errbuf := make([]byte, pcapErrBufSize)
	promiscFlag := 0
	if promisc {
		promiscFlag = 1
	}
	handle, _, _ := open.Call(
		uintptr(unsafe.Pointer(&name[0])),
		65535,
		uintptr(promiscFlag),
		200,
		uintptr(unsafe.Pointer(&errbuf[0])),
	)
	if handle == 0 {
		return nil, errors.New(cStringBytes(errbuf))
	}
	if bpf != "" {
		if err := setBPFFilter(handle, bpf); err != nil {
			closeHandle(handle)
			return nil, err
		}
	}
	datalink, err := wpcapProc("pcap_datalink")
	if err != nil {
		closeHandle(handle)
		return nil, err
	}
	link, _, _ := datalink.Call(handle)
	return &wpcapSource{handle: handle, linkType: int(link)}, nil
}

func setBPFFilter(handle uintptr, bpf string) error {
	compile, err := wpcapProc("pcap_compile")
	if err != nil {
		return err
	}
	setFilter, err := wpcapProc("pcap_setfilter")
	if err != nil {
		return err
	}
	freeCode, err := wpcapProc("pcap_freecode")
	if err != nil {
		return err
	}
	filter := append([]byte(bpf), 0)
	var program bpfProgram
	ret, _, _ := compile.Call(
		handle,
		uintptr(unsafe.Pointer(&program)),
		uintptr(unsafe.Pointer(&filter[0])),
		1,
		0xffffffff,
	)
	if int32(ret) != 0 {
		return errors.New("BPF 编译失败: " + handleError(handle))
	}
	defer freeCode.Call(uintptr(unsafe.Pointer(&program)))
	ret, _, _ = setFilter.Call(handle, uintptr(unsafe.Pointer(&program)))
	if int32(ret) != 0 {
		return errors.New("BPF 过滤规则应用失败: " + handleError(handle))
	}
	return nil
}

func closeHandle(handle uintptr) {
	if proc, err := wpcapProc("pcap_close"); err == nil {
		proc.Call(handle)
	}
}

func handleError(handle uintptr) string {
	proc, err := wpcapProc("pcap_geterr")
	if err != nil {
		return err.Error()
	}
	ret, _, _ := proc.Call(handle)
	if ret == 0 {
		return "unknown error"
	}
	return cString((*byte)(unsafe.Pointer(ret)))
}

type wpcapSource struct {
	mu       sync.Mutex
	handle   uintptr
	linkType int
	closed   bool
}

func (s *wpcapSource) LinkType() int { return s.linkType }

func (s *wpcapSource) Next(ctx context.Context) ([]byte, time.Time, int, error) {
	next, err := wpcapProc("pcap_next_ex")
	if err != nil {
		return nil, time.Time{}, 0, err
	}
	for {
		if err := ctx.Err(); err != nil {
			return nil, time.Time{}, 0, err
		}
		var header *pcapPkthdr
		var data *byte
		ret, _, _ := next.Call(
			s.handle,
			uintptr(unsafe.Pointer(&header)),
			uintptr(unsafe.Pointer(&data)),
		)
		switch int32(ret) {
		case 1:
			if header == nil || data == nil || header.Caplen == 0 {
				continue
			}
			size := int(header.Caplen)
			payload := make([]byte, size)
			copy(payload, unsafe.Slice(data, size))
			ts := time.Unix(int64(header.Sec), int64(header.Usec)*1000)
			return payload, ts, int(header.Len), nil
		case 0:
			continue
		case -1:
			return nil, time.Time{}, 0, errors.New(handleError(s.handle))
		case -2:
			return nil, time.Time{}, 0, io.EOF
		default:
			return nil, time.Time{}, 0, fmt.Errorf("pcap_next_ex 返回未知状态: %d", int32(ret))
		}
	}
}

func (s *wpcapSource) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if breakLoop, err := wpcapProc("pcap_breakloop"); err == nil {
		breakLoop.Call(s.handle)
	}
	closeHandle(s.handle)
	return nil
}

func cString(ptr *byte) string {
	if ptr == nil {
		return ""
	}
	length := 0
	for {
		value := *(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(ptr)) + uintptr(length)))
		if value == 0 || length > 1<<20 {
			break
		}
		length++
	}
	return string(unsafe.Slice(ptr, length))
}

func cStringBytes(buf []byte) string {
	if index := bytes.IndexByte(buf, 0); index >= 0 {
		return string(buf[:index])
	}
	return string(buf)
}

func sockaddrIP(addr *syscall.RawSockaddrAny) string {
	if addr == nil {
		return ""
	}
	family := *(*uint16)(unsafe.Pointer(addr))
	switch family {
	case syscall.AF_INET:
		sa := (*syscall.RawSockaddrInet4)(unsafe.Pointer(addr))
		return net.IP(sa.Addr[:]).String()
	case syscall.AF_INET6:
		sa := (*syscall.RawSockaddrInet6)(unsafe.Pointer(addr))
		return net.IP(sa.Addr[:]).String()
	default:
		return ""
	}
}
