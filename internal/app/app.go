package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/oklog/ulid/v2"

	"scanning/internal/api"
	"scanning/internal/blob"
	"scanning/internal/capture"
	"scanning/internal/config"
	"scanning/internal/event"
	"scanning/internal/flow"
	"scanning/internal/hook"
	"scanning/internal/launcher"
	"scanning/internal/mitm"
	"scanning/internal/persist"
	"scanning/internal/procinfo"
	"scanning/internal/proxy"
	"scanning/internal/rules"
	"scanning/internal/store"
	"scanning/internal/sysproxy"
	"scanning/internal/version"
)

type Options struct {
	Config   config.Config
	DataDir  string
	Dev      bool
	Headless bool
}

type App struct {
	opts       Options
	token      string
	session    flow.Session
	store      *store.Ring
	hub        *event.Hub
	certs      *mitm.Center
	blobs      *blob.Store
	rules      *rules.Store
	capture    *capture.Engine
	db         *persist.DB
	launcher   *launcher.Manager
	hook       *hook.Manager
	sysProxy   *sysproxy.Manager
	proxy      *proxy.Engine
	api        *api.Server
	httpServer *http.Server
}

type runtimeInfo struct {
	Token     string    `json:"token"`
	PID       int       `json:"pid"`
	APIAddr   string    `json:"apiAddr"`
	ProxyAddr string    `json:"proxyAddr"`
	SessionID string    `json:"sessionId"`
	Version   string    `json:"version"`
	StartedAt time.Time `json:"startedAt"`
}

func New(opts Options) (*App, error) {
	if abs, err := filepath.Abs(opts.DataDir); err == nil {
		opts.DataDir = abs
	}
	if err := config.EnsureDataDir(opts.DataDir); err != nil {
		return nil, err
	}
	if !opts.Config.Server.AllowRemote && !config.IsLoopbackAddr(opts.Config.Server.APIAddr) {
		return nil, fmt.Errorf("server.api_addr=%s 不是回环地址；如确需远程访问，请设置 server.allow_remote=true 并自行配置访问控制", opts.Config.Server.APIAddr)
	}

	token := opts.Config.Server.APIToken
	if token == "" {
		var err error
		token, err = newToken()
		if err != nil {
			return nil, fmt.Errorf("生成访问令牌: %w", err)
		}
	}

	session := flow.Session{
		ID:        ulid.Make().String(),
		Name:      "默认会话",
		Mode:      flow.ModeMixed,
		Filter:    "",
		CreatedAt: time.Now(),
	}

	st := store.NewRing(opts.Config.Store.MemoryFlows, session.ID)
	hub := event.NewHub(session.ID)

	certs, err := mitm.LoadOrCreate(filepath.Join(opts.DataDir, "certs"))
	if err != nil {
		return nil, fmt.Errorf("初始化证书中心: %w", err)
	}
	blobs, err := blob.New(filepath.Join(opts.DataDir, "blobs"))
	if err != nil {
		return nil, fmt.Errorf("初始化正文存储: %w", err)
	}
	ruleStore, err := rules.NewStore(filepath.Join(opts.DataDir, "rules.json"))
	if err != nil {
		return nil, fmt.Errorf("初始化规则存储: %w", err)
	}
	sessionDB, err := persist.Open(filepath.Join(opts.DataDir, "sessions.db"))
	if err != nil {
		return nil, fmt.Errorf("初始化会话数据库: %w", err)
	}
	appLauncher := launcher.NewManager(opts.DataDir)
	hookManager := hook.New(opts.DataDir, opts.Config.Proxy.Addr, hook.Config{
		DLLPath:    opts.Config.Hook.DLLPath,
		DLLPathX86: opts.Config.Hook.DLLPathX86,
		Ports:      opts.Config.Hook.Ports,
	})
	// Windows 下应用以挂起状态创建，先注入 Hook DLL 再恢复，确保首批网络连接也经过代理。
	appLauncher.SetStartupInjector(func(pid int) error {
		results, err := hookManager.Inject(hook.InjectRequest{PID: pid})
		if err != nil {
			return err
		}
		for _, result := range results {
			if result.Error != "" {
				return fmt.Errorf("%s", result.Error)
			}
		}
		// Hook DLL 完成首次 IAT 扫描后会发出命名事件，避免用固定休眠等待。
		if waitErr := hook.WaitReady(pid, 2*time.Second); waitErr != nil {
			slog.Warn("等待 Hook 就绪超时，继续恢复应用", "pid", pid, "error", waitErr)
		}
		return nil
	})
	sysProxyManager := sysproxy.NewManager(opts.DataDir)
	appLauncher.SetFlowCounter(func(appName string, pids []int, since time.Time) int {
		allowed := make(map[int]bool, len(pids))
		for _, pid := range pids {
			if pid > 0 {
				allowed[pid] = true
			}
		}
		count := 0
		for _, f := range st.All() {
			if f.StartedAt.Before(since) {
				continue
			}
			if len(allowed) > 0 {
				if allowed[f.Client.PID] {
					count++
				}
				continue
			}
			if appName != "" && strings.EqualFold(f.Client.App, appName) {
				count++
			}
		}
		return count
	})
	proxyEngine := proxy.New(proxy.FromConfig(opts.Config.Proxy), proxy.Deps{
		Certs:     certs,
		Store:     st,
		Hub:       hub,
		Blobs:     blobs,
		Rules:     ruleStore,
		Processes: procinfo.New(),
		SessionID: session.ID,
	})
	captureEngine := capture.New(capture.Config{
		BufferPackets: opts.Config.Capture.BufferPackets,
		MaxBodyBytes:  opts.Config.Proxy.MaxBodyBytes,
		Mirror:        opts.Config.Capture.Mirror,
	}, capture.Deps{
		Flows:     st,
		Blobs:     blobs,
		Hub:       hub,
		SessionID: session.ID,
	})
	proxyEngine.SetFlowObserver(func(f *flow.Flow) {
		go captureEngine.MirrorFlow(f)
	})

	if opts.Config.Demo.Enabled && opts.Config.Demo.Seed > 0 {
		for _, f := range flow.Generate(opts.Config.Demo.Seed) {
			st.Add(f)
		}
	}

	a := &App{
		opts:     opts,
		token:    token,
		session:  session,
		store:    st,
		hub:      hub,
		certs:    certs,
		blobs:    blobs,
		rules:    ruleStore,
		capture:  captureEngine,
		db:       sessionDB,
		launcher: appLauncher,
		hook:     hookManager,
		sysProxy: sysProxyManager,
		proxy:    proxyEngine,
	}
	a.api = api.New(api.Options{
		Config:   opts.Config,
		Store:    st,
		Hub:      hub,
		Proxy:    proxyEngine,
		Certs:    certs,
		Blobs:    blobs,
		Rules:    ruleStore,
		Capture:  captureEngine,
		DB:       sessionDB,
		Launcher: appLauncher,
		Hook:     hookManager,
		SysProxy: sysProxyManager,
		Token:    token,
		Session:  session,
		DataDir:  opts.DataDir,
		Dev:      opts.Dev,
		Headless: opts.Headless,
	})
	a.httpServer = &http.Server{
		Handler:           a.api.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       90 * time.Second,
	}

	if err := writeRuntime(opts.DataDir, runtimeInfo{
		Token:     token,
		PID:       os.Getpid(),
		APIAddr:   opts.Config.Server.APIAddr,
		ProxyAddr: opts.Config.Proxy.Addr,
		SessionID: session.ID,
		Version:   version.String(),
		StartedAt: time.Now(),
	}); err != nil {
		return nil, err
	}

	return a, nil
}

func (a *App) Handler() http.Handler {
	return a.api.Handler()
}

func (a *App) Run(parent context.Context) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	listener, err := net.Listen("tcp", a.opts.Config.Server.APIAddr)
	if err != nil {
		return fmt.Errorf("监听 %s: %w", a.opts.Config.Server.APIAddr, err)
	}

	url := "http://" + listener.Addr().String()
	slog.Info("Scanning M5 已启动",
		"url", url,
		"data_dir", a.opts.DataDir,
		"dev", a.opts.Dev,
		"headless", a.opts.Headless,
	)

	go a.statsLoop(ctx)
	if a.opts.Config.Demo.IntervalSeconds > 0 {
		go a.demoLoop(ctx, time.Duration(a.opts.Config.Demo.IntervalSeconds)*time.Second)
	}

	if a.opts.Config.Proxy.Enabled {
		if err := a.proxy.Start(); err != nil {
			slog.Warn("HTTP/HTTPS 代理启动失败", "error", err)
		} else {
			if a.hook != nil {
				a.hook.SetProxyAddr(a.proxy.Status().Addr)
			}
			a.hub.Broadcast("proxy.status", a.proxy.Status())
		}
	}

	if a.opts.Config.Server.OpenBrowser && !a.opts.Dev && !a.opts.Headless {
		go func() {
			time.Sleep(250 * time.Millisecond)
			openBrowser(url)
		}()
	}

	errCh := make(chan error, 1)
	go func() {
		err := a.httpServer.Serve(listener)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
	case err := <-errCh:
		return err
	}

	shutdownCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	_ = a.proxy.Stop(shutdownCtx)
	if a.sysProxy != nil {
		if err := a.sysProxy.RestoreIfApplied(); err != nil {
			slog.Warn("退出时还原系统代理失败", "error", err)
		}
	}
	if a.capture != nil {
		_ = a.capture.Stop(shutdownCtx)
	}
	_ = a.httpServer.Shutdown(shutdownCtx)
	a.hub.Close()
	if a.db != nil {
		_ = a.db.Close()
	}
	return nil
}

func (a *App) statsLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.hub.Broadcast("stats", a.api.StatsData())
			if a.capture != nil {
				a.hub.Broadcast("capture.status", a.capture.Status())
			}
		}
	}
}

func (a *App) demoLoop(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for _, f := range flow.Generate(1) {
				added := a.store.Add(f)
				a.hub.Broadcast("flow.created", added.Summary())
			}
		}
	}
}

func writeRuntime(dir string, info runtimeInfo) error {
	data, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(dir, "runtime.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("写入 %s: %w", path, err)
	}
	if runtime.GOOS != "windows" {
		_ = os.Chmod(path, 0o600)
	}
	return nil
}

func newToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	if err := cmd.Start(); err != nil {
		slog.Debug("打开浏览器失败", "error", err, "url", url)
	}
}
