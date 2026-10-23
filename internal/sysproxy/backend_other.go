//go:build !windows

package sysproxy

import (
	"errors"
	"runtime"
)

type unsupportedBackend struct{}

func newBackend() backend { return unsupportedBackend{} }

func (unsupportedBackend) platform() string { return runtime.GOOS }

func (unsupportedBackend) supported() bool { return false }

func (unsupportedBackend) read() (Config, error) { return Config{}, nil }

func (unsupportedBackend) write(Config) error {
	return errors.New("当前平台暂不支持一键接管系统代理，请手动设置")
}

func (unsupportedBackend) notify() {}
