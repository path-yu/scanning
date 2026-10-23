//go:build !wpcap

package capture

import (
	"errors"
)

type stubBackend struct{}

func newBackend() Backend { return stubBackend{} }

func (stubBackend) Name() string { return "纯 Go 构建" }

func (stubBackend) Available() (bool, string) {
	return false, "当前构建未启用实时网卡抓包；可使用「导入 PCAP」或「代理镜像」，或安装 Npcap 后以 -tags wpcap 重新构建"
}

func (stubBackend) InstallHint() []string {
	return []string{
		"安装 Npcap 1.x（安装时勾选 WinPcap 兼容模式）：https://npcap.com/#download",
		"使用 go build -tags wpcap ./cmd/scanning 重新构建，即可在实时网卡列表中看到 Npcap 设备",
		"无驱动/无管理员权限时，可使用「导入 PCAP」或「代理镜像」查看报文",
	}
}

func (stubBackend) Interfaces() ([]InterfaceInfo, error) {
	return systemInterfaces(), nil
}

func (stubBackend) Open(string, string, bool) (Source, error) {
	return nil, errors.New("当前构建未启用实时网卡抓包")
}
