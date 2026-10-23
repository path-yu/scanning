//go:build windows

package sysproxy

import (
	"errors"
	"fmt"
	"syscall"

	"golang.org/x/sys/windows/registry"
)

const internetSettingsKey = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`

type windowsBackend struct{}

func newBackend() backend { return windowsBackend{} }

func (windowsBackend) platform() string { return "windows" }

func (windowsBackend) supported() bool { return true }

func (windowsBackend) read() (Config, error) {
	key, err := registry.OpenKey(registry.CURRENT_USER, internetSettingsKey, registry.QUERY_VALUE)
	if err != nil {
		return Config{}, fmt.Errorf("打开 Internet Settings 失败: %w", err)
	}
	defer key.Close()

	var cfg Config
	if value, _, err := key.GetIntegerValue("ProxyEnable"); err == nil {
		cfg.ProxyEnable = int(value)
	}
	if value, _, err := key.GetStringValue("ProxyServer"); err == nil {
		cfg.ProxyServer = value
	}
	if value, _, err := key.GetStringValue("ProxyOverride"); err == nil {
		cfg.ProxyOverride = value
	}
	if value, _, err := key.GetStringValue("AutoConfigURL"); err == nil {
		cfg.AutoConfigURL = value
	}
	return cfg, nil
}

func (windowsBackend) write(cfg Config) error {
	key, err := registry.OpenKey(registry.CURRENT_USER, internetSettingsKey, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("打开 Internet Settings 失败: %w", err)
	}
	defer key.Close()

	if err := key.SetDWordValue("ProxyEnable", uint32(cfg.ProxyEnable)); err != nil {
		return fmt.Errorf("写入 ProxyEnable 失败: %w", err)
	}
	if err := setOrDeleteString(key, "ProxyServer", cfg.ProxyServer); err != nil {
		return fmt.Errorf("写入 ProxyServer 失败: %w", err)
	}
	if err := setOrDeleteString(key, "ProxyOverride", cfg.ProxyOverride); err != nil {
		return fmt.Errorf("写入 ProxyOverride 失败: %w", err)
	}
	if err := setOrDeleteString(key, "AutoConfigURL", cfg.AutoConfigURL); err != nil {
		return fmt.Errorf("写入 AutoConfigURL 失败: %w", err)
	}
	return nil
}

func setOrDeleteString(key registry.Key, name, value string) error {
	if value == "" {
		if err := key.DeleteValue(name); err != nil && !errors.Is(err, registry.ErrNotExist) {
			return err
		}
		return nil
	}
	return key.SetStringValue(name, value)
}

var (
	wininet                = syscall.NewLazyDLL("wininet.dll")
	procInternetSetOptionW = wininet.NewProc("InternetSetOptionW")
)

func (windowsBackend) notify() {
	const (
		internetOptionRefresh         = 37
		internetOptionSettingsChanged = 39
	)
	procInternetSetOptionW.Call(0, internetOptionSettingsChanged, 0, 0)
	procInternetSetOptionW.Call(0, internetOptionRefresh, 0, 0)
}
