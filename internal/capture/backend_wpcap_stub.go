//go:build wpcap && !windows

package capture

import "errors"

type wpcapUnsupportedBackend struct{}

func newBackend() Backend { return wpcapUnsupportedBackend{} }

func (wpcapUnsupportedBackend) Name() string { return "Npcap" }

func (wpcapUnsupportedBackend) Available() (bool, string) {
	return false, "当前平台不支持 Npcap 实时抓包"
}

func (wpcapUnsupportedBackend) InstallHint() []string {
	return []string{"Npcap 实时抓包仅在 Windows 构建中提供", "可改用导入 PCAP 或代理镜像"}
}

func (wpcapUnsupportedBackend) Interfaces() ([]InterfaceInfo, error) {
	return systemInterfaces(), nil
}

func (wpcapUnsupportedBackend) Open(string, string, bool) (Source, error) {
	return nil, errors.New("当前平台不支持 Npcap 实时抓包")
}
