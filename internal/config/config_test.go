package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseUpstreamProxy(t *testing.T) {
	cases := []struct {
		raw    string
		scheme string
		host   string
		wantE  bool
	}{
		{raw: ""},
		{raw: "127.0.0.1:7890", scheme: "http", host: "127.0.0.1:7890"},
		{raw: "http://127.0.0.1:7890", scheme: "http", host: "127.0.0.1:7890"},
		{raw: "HTTPS://proxy.example.com:8443", scheme: "https", host: "proxy.example.com:8443"},
		{raw: "http://user:pass@127.0.0.1:7890", scheme: "http", host: "127.0.0.1:7890"},
		{raw: "socks5://127.0.0.1:1080", wantE: true},
		{raw: "http://proxy.example.com/path", wantE: true},
		{raw: "http://", wantE: true},
		{raw: "http://proxy.example.com:7890?x=1", wantE: true},
	}
	for _, tc := range cases {
		u, err := ParseUpstreamProxy(tc.raw)
		if tc.wantE {
			if err == nil {
				t.Fatalf("%q 期望报错，得到 %+v", tc.raw, u)
			}
			continue
		}
		if tc.raw == "" {
			if u != nil || err != nil {
				t.Fatalf("空配置应返回 nil,nil，得到 %+v, %v", u, err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%q 解析失败: %v", tc.raw, err)
		}
		if u.Scheme != tc.scheme || u.Host != tc.host {
			t.Fatalf("%q => %s://%s，期望 %s://%s", tc.raw, u.Scheme, u.Host, tc.scheme, tc.host)
		}
	}
}

func TestLoadNormalizesUpstreamProxy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	body := "proxy:\n  upstream_proxy: 127.0.0.1:7890\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Proxy.UpstreamProxy != "http://127.0.0.1:7890" {
		t.Fatalf("upstream_proxy = %q", cfg.Proxy.UpstreamProxy)
	}
}

func TestLoadRejectsInvalidUpstreamProxy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	body := "proxy:\n  upstream_proxy: socks5://127.0.0.1:1080\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "upstream_proxy") {
		t.Fatalf("期望 upstream_proxy 校验错误，得到 %v", err)
	}
}

func TestDefaultDemoDisabled(t *testing.T) {
	if Default().Demo.Enabled {
		t.Fatal("生产默认配置不应启用演示数据")
	}
}
