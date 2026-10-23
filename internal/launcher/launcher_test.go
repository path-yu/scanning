package launcher

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestBuildEnvOverridesProxy(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://old:1")
	t.Setenv("ALL_PROXY", "socks5://old:2")
	t.Setenv("NO_PROXY", "example.com")
	env := BuildEnv("127.0.0.1:8899", map[string]string{"CUSTOM": "1"})

	values := make(map[string][]string)
	for _, item := range env {
		key, value, ok := strings.Cut(item, "=")
		if !ok {
			continue
		}
		values[key] = append(values[key], value)
	}
	for _, key := range []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "NO_PROXY", "no_proxy"} {
		if len(values[key]) != 1 {
			t.Fatalf("%s 应只有一条，实际 %v", key, values[key])
		}
	}
	for _, key := range []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"} {
		if values[key][0] != "http://127.0.0.1:8899" {
			t.Fatalf("%s = %q", key, values[key][0])
		}
	}
	if _, ok := values["ALL_PROXY"]; ok {
		t.Fatalf("不应保留 ALL_PROXY: %v", values["ALL_PROXY"])
	}
	if got := values["NO_PROXY"][0]; !strings.Contains(got, "127.0.0.1") || !strings.Contains(got, "localhost") {
		t.Fatalf("NO_PROXY = %q", got)
	}
	if values["CUSTOM"][0] != "1" {
		t.Fatalf("自定义环境变量丢失: %v", values["CUSTOM"])
	}
}

func TestValidateExecutable(t *testing.T) {
	if _, err := validateExecutable(""); err == nil {
		t.Fatal("空路径应报错")
	}
	dir := t.TempDir()
	if _, err := validateExecutable(dir); err == nil {
		t.Fatal("目录应报错")
	}
	name := "demo-app"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("x"), 0o700); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := validateExecutable(path); err != nil {
		t.Fatalf("可执行文件校验失败: %v", err)
	}
}

func TestValidateExecutableRejectsScriptOnWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows 专用")
	}
	path := filepath.Join(t.TempDir(), "demo.bat")
	if err := os.WriteFile(path, []byte("echo hi"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := validateExecutable(path); err == nil {
		t.Fatal("批处理文件应被拒绝")
	}
}

func TestNormalizeEnv(t *testing.T) {
	if _, err := normalizeEnv(map[string]string{"BAD=KEY": "1"}); err == nil {
		t.Fatal("非法变量名应报错")
	}
	if _, err := normalizeEnv(map[string]string{"OK": "a\x00b"}); err == nil {
		t.Fatal("NUL 值应报错")
	}
}

func TestRecentPersistence(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(dir)
	now := time.Now()
	m.mu.Lock()
	m.upsertRecentLocked(&App{Name: "demo.exe", Path: `C:\demo\demo.exe`, Args: []string{"--x"}, Cwd: `C:\demo`}, now)
	m.mu.Unlock()

	reloaded := NewManager(dir)
	recent := reloaded.Recent()
	if len(recent) != 1 {
		t.Fatalf("recent = %+v", recent)
	}
	if recent[0].Path != `C:\demo\demo.exe` || len(recent[0].Args) != 1 {
		t.Fatalf("recent[0] = %+v", recent[0])
	}
}

func TestLaunchRejectsEmptyProxy(t *testing.T) {
	if _, err := NewManager(t.TempDir()).Launch("", LaunchRequest{Path: "x"}); err == nil {
		t.Fatal("空代理地址应报错")
	}
}

func TestBuildDiagnosis(t *testing.T) {
	proxy := "127.0.0.1:8899"
	diag := buildDiagnosis(3, 0, nil, proxy)
	if diag.Status != "proxy" || diag.Flows != 3 || !strings.Contains(diag.Message, "3") {
		t.Fatalf("proxy diagnosis = %+v", diag)
	}

	diag = buildDiagnosis(0, 2, nil, proxy)
	if diag.Status != "proxy" || diag.Proxied != 2 {
		t.Fatalf("proxied diagnosis = %+v", diag)
	}

	diag = buildDiagnosis(0, 0, map[string]int{
		"111.124.200.67:443": 3,
		"58.49.156.86:443":   2,
		"27.18.12.12:443":    1,
	}, proxy)
	if diag.Status != "direct" || len(diag.Direct) != 3 {
		t.Fatalf("direct diagnosis = %+v", diag)
	}
	if diag.Direct[0].Address != "111.124.200.67" || diag.Direct[0].Port != 443 || diag.Direct[0].Count != 3 {
		t.Fatalf("direct[0] = %+v", diag.Direct[0])
	}
	if !strings.Contains(diag.Message, "直连") {
		t.Fatalf("message = %q", diag.Message)
	}

	diag = buildDiagnosis(0, 0, nil, proxy)
	if diag.Status != "unknown" {
		t.Fatalf("empty diagnosis = %+v", diag)
	}
}

func TestTopEndpointsLimit(t *testing.T) {
	direct := make(map[string]int)
	for i := 1; i <= 8; i++ {
		direct[fmt.Sprintf("10.0.0.%d:443", i)] = i
	}
	items := topEndpoints(direct, 5)
	if len(items) != 5 {
		t.Fatalf("len = %d", len(items))
	}
	if items[0].Address != "10.0.0.8" || items[0].Count != 8 {
		t.Fatalf("items[0] = %+v", items[0])
	}
}

func TestProxyHelpers(t *testing.T) {
	if portOf("127.0.0.1:8899") != 8899 {
		t.Fatal("portOf 错误")
	}
	if portOf("bad") != 0 {
		t.Fatal("portOf 无效输入应返回 0")
	}
	if !isLoopbackIP("127.0.0.1") || !isLoopbackIP("::1") {
		t.Fatal("回环地址识别失败")
	}
	if isLoopbackIP("10.0.0.1") {
		t.Fatal("非回环地址识别错误")
	}
}
