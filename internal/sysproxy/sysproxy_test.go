package sysproxy

import (
	"strings"
	"sync"
	"testing"
)

type fakeBackend struct {
	mu          sync.Mutex
	cfg         Config
	isSupported bool
	writes      int
	notifies    int
	failWrite   bool
}

func (f *fakeBackend) platform() string { return "test" }

func (f *fakeBackend) read() (Config, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cfg, nil
}

func (f *fakeBackend) write(cfg Config) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.writes++
	if f.failWrite {
		f.failWrite = false
		return assertError("write failed")
	}
	f.cfg = cfg
	return nil
}

func (f *fakeBackend) notify() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.notifies++
}

func (f *fakeBackend) supported() bool { return f.isSupported }

type assertError string

func (e assertError) Error() string { return string(e) }

func TestApplyAndRestore(t *testing.T) {
	original := Config{
		ProxyEnable:   1,
		ProxyServer:   "127.0.0.1:7890",
		ProxyOverride: "*.steamcontent.com;localhost",
		AutoConfigURL: "http://example.com/proxy.pac",
	}
	fake := &fakeBackend{isSupported: true, cfg: original}
	manager := newManager(t.TempDir(), fake)

	status, err := manager.Apply("127.0.0.1:8899")
	if err != nil {
		t.Fatal(err)
	}
	if !status.Active || status.AppliedProxy != "127.0.0.1:8899" {
		t.Fatalf("status = %+v", status)
	}
	current := fake.cfg
	if current.ProxyEnable != 1 || current.ProxyServer != "127.0.0.1:8899" {
		t.Fatalf("applied config = %+v", current)
	}
	if current.AutoConfigURL != "" {
		t.Fatalf("PAC 应被清空: %+v", current)
	}
	for _, want := range []string{"localhost", "127.*", "<local>", "*.steamcontent.com"} {
		if !strings.Contains(current.ProxyOverride, want) {
			t.Fatalf("override 缺少 %q: %s", want, current.ProxyOverride)
		}
	}
	if fake.notifies == 0 {
		t.Fatal("应通知系统代理变更")
	}

	if _, err := manager.Apply("127.0.0.1:8899"); err != nil {
		t.Fatalf("重复接管应幂等: %v", err)
	}

	status, err = manager.Restore()
	if err != nil {
		t.Fatal(err)
	}
	if status.Active {
		t.Fatalf("还原后仍为接管状态: %+v", status)
	}
	if fake.cfg != original {
		t.Fatalf("还原配置 = %+v，期望 %+v", fake.cfg, original)
	}
	if _, err := manager.Restore(); err == nil {
		t.Fatal("无备份时还原应报错")
	}
}

func TestApplyWriteFailureRollsBack(t *testing.T) {
	original := Config{ProxyEnable: 1, ProxyServer: "127.0.0.1:7890"}
	fake := &fakeBackend{isSupported: true, cfg: original, failWrite: true}
	manager := newManager(t.TempDir(), fake)

	if _, err := manager.Apply("127.0.0.1:8899"); err == nil {
		t.Fatal("写入失败应返回错误")
	}
	if fake.cfg != original {
		t.Fatalf("失败后未回滚: %+v", fake.cfg)
	}
	status, err := manager.Status()
	if err != nil {
		t.Fatal(err)
	}
	if status.Active {
		t.Fatalf("失败后不应保留 active 备份: %+v", status)
	}
}

func TestStaleBackupAndRestoreIfApplied(t *testing.T) {
	fake := &fakeBackend{isSupported: true, cfg: Config{ProxyEnable: 1, ProxyServer: "127.0.0.1:7890"}}
	manager := newManager(t.TempDir(), fake)
	if _, err := manager.Apply("127.0.0.1:8899"); err != nil {
		t.Fatal(err)
	}

	fake.mu.Lock()
	fake.cfg.ProxyServer = "127.0.0.1:9999"
	fake.mu.Unlock()

	status, err := manager.Status()
	if err != nil {
		t.Fatal(err)
	}
	if !status.Active || !strings.Contains(status.Message, "其他程序修改") {
		t.Fatalf("stale status = %+v", status)
	}
	if err := manager.RestoreIfApplied(); err != nil {
		t.Fatal(err)
	}
	if fake.cfg.ProxyServer != "127.0.0.1:9999" {
		t.Fatalf("用户已修改的系统代理不应被覆盖: %+v", fake.cfg)
	}
}

func TestRestoreIfApplied(t *testing.T) {
	fake := &fakeBackend{isSupported: true, cfg: Config{ProxyEnable: 1, ProxyServer: "127.0.0.1:7890"}}
	manager := newManager(t.TempDir(), fake)
	if _, err := manager.Apply("127.0.0.1:8899"); err != nil {
		t.Fatal(err)
	}
	if err := manager.RestoreIfApplied(); err != nil {
		t.Fatal(err)
	}
	if fake.cfg.ProxyServer != "127.0.0.1:7890" {
		t.Fatalf("退出时未还原: %+v", fake.cfg)
	}
	status, err := manager.Status()
	if err != nil {
		t.Fatal(err)
	}
	if status.Active {
		t.Fatalf("还原后仍 active: %+v", status)
	}
}

func TestUnsupportedBackend(t *testing.T) {
	fake := &fakeBackend{isSupported: false}
	manager := newManager(t.TempDir(), fake)
	status, err := manager.Status()
	if err != nil {
		t.Fatal(err)
	}
	if status.Supported {
		t.Fatal("应标记为不支持")
	}
	if _, err := manager.Apply("127.0.0.1:8899"); err == nil {
		t.Fatal("不支持的平台应报错")
	}
}

func TestMergeOverride(t *testing.T) {
	got := mergeOverride("localhost;*.example.com;127.*")
	if got != "localhost;*.example.com;127.*;<local>" {
		t.Fatalf("mergeOverride = %q", got)
	}
	if got := mergeOverride(""); got != "localhost;127.*;<local>" {
		t.Fatalf("empty mergeOverride = %q", got)
	}
}
