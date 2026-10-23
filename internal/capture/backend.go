package capture

import (
	"context"
	"net"
	"time"
)

type Source interface {
	LinkType() int
	Next(ctx context.Context) ([]byte, time.Time, int, error)
	Close() error
}

type Backend interface {
	Name() string
	Available() (bool, string)
	InstallHint() []string
	Interfaces() ([]InterfaceInfo, error)
	Open(iface, bpf string, promisc bool) (Source, error)
}

func systemInterfaces() []InterfaceInfo {
	items, err := net.Interfaces()
	if err != nil {
		return []InterfaceInfo{}
	}
	out := make([]InterfaceInfo, 0, len(items))
	defaultAssigned := false
	for _, item := range items {
		info := InterfaceInfo{
			Name:        item.Name,
			Description: item.Name,
			Loopback:    item.Flags&net.FlagLoopback != 0,
		}
		if addrs, err := item.Addrs(); err == nil {
			for _, addr := range addrs {
				info.Addresses = append(info.Addresses, addr.String())
			}
		}
		if !info.Loopback && !defaultAssigned && len(info.Addresses) > 0 {
			info.Default = true
			defaultAssigned = true
		}
		out = append(out, info)
	}
	return out
}
