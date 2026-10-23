package browser

import (
	"strings"
	"testing"
)

func TestNormalizeURL(t *testing.T) {
	cases := []struct {
		raw   string
		want  string
		wantE bool
	}{
		{raw: "", want: "https://example.com"},
		{raw: "https://example.com/path?q=1", want: "https://example.com/path?q=1"},
		{raw: "http://127.0.0.1:8898", want: "http://127.0.0.1:8898"},
		{raw: "file:///etc/passwd", wantE: true},
		{raw: "javascript:alert(1)", wantE: true},
		{raw: "https://", wantE: true},
	}
	for _, tc := range cases {
		got, err := NormalizeURL(tc.raw)
		if tc.wantE {
			if err == nil {
				t.Fatalf("%q 期望报错，得到 %q", tc.raw, got)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%q 解析失败: %v", tc.raw, err)
		}
		if got != tc.want {
			t.Fatalf("%q => %q，期望 %q", tc.raw, got, tc.want)
		}
	}
}

func TestBuildArgs(t *testing.T) {
	args := BuildArgs("127.0.0.1:8899", `C:\data\browser-profile`, "https://example.com/")
	joined := strings.Join(args, "\n")
	for _, want := range []string{
		"--proxy-server=http://127.0.0.1:8899",
		`--user-data-dir=C:\data\browser-profile`,
		"--no-first-run",
		"--no-default-browser-check",
		"https://example.com/",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("参数缺少 %q: %v", want, args)
		}
	}
	if args[len(args)-1] != "https://example.com/" {
		t.Fatalf("URL 应为最后一个参数: %v", args)
	}
}

func TestLaunchRejectsEmptyProxy(t *testing.T) {
	if _, err := Launch(Options{}); err == nil {
		t.Fatal("代理地址为空时应报错")
	}
}

func TestLaunchRejectsUnsupportedBrowser(t *testing.T) {
	_, err := Launch(Options{
		ProxyAddr: "127.0.0.1:8899",
		DataDir:   t.TempDir(),
		Preferred: "firefox",
	})
	if err == nil || !strings.Contains(err.Error(), "不支持") {
		t.Fatalf("期望浏览器类型错误，得到 %v", err)
	}
}
