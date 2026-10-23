package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config 是 M0 阶段实际使用的配置子集，字段命名与设计文档保持一致。
type Config struct {
	Server  ServerConfig  `yaml:"server"`
	Proxy   ProxyConfig   `yaml:"proxy"`
	Hook    HookConfig    `yaml:"hook"`
	Capture CaptureConfig `yaml:"capture"`
	Store   StoreConfig   `yaml:"store"`
	Demo    DemoConfig    `yaml:"demo"`
	Logging LoggingConfig `yaml:"logging"`
}

type ServerConfig struct {
	APIAddr     string `yaml:"api_addr"`
	OpenBrowser bool   `yaml:"open_browser"`
	AllowRemote bool   `yaml:"allow_remote"`
	APIToken    string `yaml:"api_token"`
}

type ProxyConfig struct {
	Enabled                    bool     `yaml:"enabled"`
	Addr                       string   `yaml:"addr"`
	MITM                       bool     `yaml:"mitm"`
	Passthrough                []string `yaml:"passthrough"`
	UpstreamProxy              string   `yaml:"upstream_proxy"`
	UpstreamInsecureSkipVerify bool     `yaml:"upstream_insecure_skip_verify"`
	MaxBodyBytes               int64    `yaml:"max_body_bytes"`
	BreakpointTimeoutSeconds   int      `yaml:"breakpoint_timeout_seconds"`
}

type CaptureConfig struct {
	Enabled       bool   `yaml:"enabled"`
	BPF           string `yaml:"bpf"`
	BufferPackets int    `yaml:"buffer_packets"`
	Mirror        bool   `yaml:"mirror"`
}

// HookConfig 控制 Windows 进程注入模式。DLL 路径留空时按可执行文件目录自动查找。
type HookConfig struct {
	DLLPath string `yaml:"dll_path"`
	Ports   []int  `yaml:"ports"`
}

type StoreConfig struct {
	MemoryFlows int `yaml:"memory_flows"`
}

type DemoConfig struct {
	Enabled         bool `yaml:"enabled"`
	Seed            int  `yaml:"seed"`
	IntervalSeconds int  `yaml:"interval_seconds"`
}

type LoggingConfig struct {
	Level string `yaml:"level"`
}

func Default() Config {
	return Config{
		Server: ServerConfig{
			APIAddr:     "127.0.0.1:8898",
			OpenBrowser: true,
		},
		Proxy: ProxyConfig{
			Enabled:                  true,
			Addr:                     "127.0.0.1:8899",
			MITM:                     true,
			Passthrough:              []string{"*.apple.com", "*.microsoft.com", "*.windowsupdate.com"},
			MaxBodyBytes:             10 << 20,
			BreakpointTimeoutSeconds: 60,
		},
		Capture: CaptureConfig{
			Enabled:       false,
			BPF:           "tcp or udp or icmp or icmp6",
			BufferPackets: 20000,
		},
		Store: StoreConfig{
			MemoryFlows: 50000,
		},
		Hook: HookConfig{
			Ports: []int{80, 443},
		},
		Demo: DemoConfig{
			Enabled: false,
			Seed:    80,
		},
		Logging: LoggingConfig{
			Level: "info",
		},
	}
}

// Load 读取配置。path 为空时尝试读取数据目录下的 config.yaml，不存在则使用默认值；
// path 非空时必须存在。
func Load(path string) (Config, error) {
	cfg := Default()

	if path == "" {
		path = filepath.Join(DefaultDataDir(), "config.yaml")
		data, err := os.ReadFile(path)
		switch {
		case err == nil:
			if err := yaml.Unmarshal(data, &cfg); err != nil {
				return cfg, fmt.Errorf("解析配置 %s: %w", path, err)
			}
		case errors.Is(err, os.ErrNotExist):
			// 使用默认配置
		default:
			return cfg, fmt.Errorf("读取配置 %s: %w", path, err)
		}
	} else {
		data, err := os.ReadFile(path)
		if err != nil {
			return cfg, fmt.Errorf("读取配置 %s: %w", path, err)
		}
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return cfg, fmt.Errorf("解析配置 %s: %w", path, err)
		}
	}

	if cfg.Store.MemoryFlows <= 0 {
		cfg.Store.MemoryFlows = Default().Store.MemoryFlows
	}
	if cfg.Server.APIAddr == "" {
		cfg.Server.APIAddr = Default().Server.APIAddr
	}
	if cfg.Proxy.MaxBodyBytes <= 0 {
		cfg.Proxy.MaxBodyBytes = Default().Proxy.MaxBodyBytes
	}
	if cfg.Proxy.BreakpointTimeoutSeconds <= 0 {
		cfg.Proxy.BreakpointTimeoutSeconds = Default().Proxy.BreakpointTimeoutSeconds
	}
	if parsed, err := ParseUpstreamProxy(cfg.Proxy.UpstreamProxy); err != nil {
		return cfg, err
	} else if parsed != nil {
		cfg.Proxy.UpstreamProxy = parsed.String()
	}
	if cfg.Capture.BufferPackets <= 0 {
		cfg.Capture.BufferPackets = Default().Capture.BufferPackets
	}
	if cfg.Capture.BPF == "" {
		cfg.Capture.BPF = Default().Capture.BPF
	}
	if len(cfg.Hook.Ports) == 0 {
		cfg.Hook.Ports = Default().Hook.Ports
	}
	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func (c Config) Validate() error {
	if _, _, err := net.SplitHostPort(c.Server.APIAddr); err != nil {
		return fmt.Errorf("server.api_addr 无效: %w", err)
	}
	if c.Proxy.Addr != "" {
		if _, _, err := net.SplitHostPort(c.Proxy.Addr); err != nil {
			return fmt.Errorf("proxy.addr 无效: %w", err)
		}
	}
	if _, err := ParseUpstreamProxy(c.Proxy.UpstreamProxy); err != nil {
		return err
	}
	if c.Proxy.MaxBodyBytes < 1024 {
		return fmt.Errorf("proxy.max_body_bytes 至少为 1024")
	}
	if c.Proxy.BreakpointTimeoutSeconds < 5 || c.Proxy.BreakpointTimeoutSeconds > 600 {
		return fmt.Errorf("proxy.breakpoint_timeout_seconds 需在 5 到 600 之间")
	}
	if c.Store.MemoryFlows < 100 || c.Store.MemoryFlows > 200000 {
		return fmt.Errorf("store.memory_flows 需在 100 到 200000 之间")
	}
	if c.Demo.Seed < 0 || c.Demo.Seed > 5000 {
		return fmt.Errorf("demo.seed 需在 0 到 5000 之间")
	}
	if c.Demo.IntervalSeconds < 0 {
		return fmt.Errorf("demo.interval_seconds 不能为负数")
	}
	if c.Capture.BufferPackets < 100 || c.Capture.BufferPackets > 200000 {
		return fmt.Errorf("capture.buffer_packets 需在 100 到 200000 之间")
	}
	for _, port := range c.Hook.Ports {
		if port <= 0 || port > 65535 {
			return fmt.Errorf("hook.ports 包含无效端口 %d", port)
		}
	}
	return nil
}

func DefaultDataDir() string {
	switch runtime.GOOS {
	case "windows":
		base := os.Getenv("APPDATA")
		if base == "" {
			if dir, err := os.UserConfigDir(); err == nil {
				base = dir
			}
		}
		if base == "" {
			base = "."
		}
		return filepath.Join(base, "Scanning")
	case "darwin":
		home, _ := os.UserHomeDir()
		return filepath.Join(home, "Library", "Application Support", "Scanning")
	default:
		if xdg := os.Getenv("XDG_DATA_HOME"); xdg != "" {
			return filepath.Join(xdg, "scanning")
		}
		home, _ := os.UserHomeDir()
		return filepath.Join(home, ".local", "share", "scanning")
	}
}

func EnsureDataDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("创建数据目录 %s: %w", dir, err)
	}
	return nil
}

// ParseUpstreamProxy 解析上游代理地址；允许省略 http:// 前缀，仅支持 http/https 代理。
func ParseUpstreamProxy(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("proxy.upstream_proxy 无效: %w", err)
	}
	u.Scheme = strings.ToLower(u.Scheme)
	switch u.Scheme {
	case "http", "https":
	default:
		return nil, fmt.Errorf("proxy.upstream_proxy 仅支持 http/https，当前为 %q", u.Scheme)
	}
	if u.Hostname() == "" {
		return nil, errors.New("proxy.upstream_proxy 缺少主机")
	}
	if u.Path != "" && u.Path != "/" {
		return nil, errors.New("proxy.upstream_proxy 不能包含路径")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("proxy.upstream_proxy 不能包含查询参数或片段")
	}
	return u, nil
}

func IsLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	host = strings.TrimSpace(host)
	if host == "" || host == "0.0.0.0" || host == "::" {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return strings.EqualFold(host, "localhost")
	}
	return ip.IsLoopback()
}
