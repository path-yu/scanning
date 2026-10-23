package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"

	"scanning/internal/app"
	"scanning/internal/config"
	"scanning/internal/version"
)

func main() {
	var (
		configPath  string
		addr        string
		dataDir     string
		dev         bool
		headless    bool
		noOpen      bool
		noProxy     bool
		showVersion bool
	)

	flag.StringVar(&configPath, "config", "", "配置文件路径（默认读取数据目录下的 config.yaml）")
	flag.StringVar(&addr, "addr", "", "控制台/API 监听地址，例如 127.0.0.1:8898")
	flag.StringVar(&dataDir, "data-dir", "", "数据目录（默认使用平台标准目录）")
	flag.BoolVar(&dev, "dev", false, "开发模式：允许 Vite 开发服务器访问 API，并跳过鉴权")
	flag.BoolVar(&headless, "headless", false, "无头模式：不提供 Web UI")
	flag.BoolVar(&noOpen, "no-open", false, "启动后不自动打开浏览器")
	flag.BoolVar(&noProxy, "no-proxy", false, "启动时不自动开启 HTTP/HTTPS 代理")
	flag.BoolVar(&showVersion, "version", false, "输出版本并退出")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Scanning 抓包工具 M5\n\n用法: %s [选项]\n\n", os.Args[0])
		flag.PrintDefaults()
		fmt.Fprintln(flag.CommandLine.Output(), "\n示例:")
		fmt.Fprintln(flag.CommandLine.Output(), "  scanning --dev")
		fmt.Fprintln(flag.CommandLine.Output(), "  scanning --headless --addr 127.0.0.1:8898")
	}
	flag.Parse()

	if showVersion {
		fmt.Println(version.String())
		return
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "加载配置失败:", err)
		os.Exit(1)
	}
	if addr != "" {
		cfg.Server.APIAddr = addr
	}
	if err := cfg.Validate(); err != nil {
		fmt.Fprintln(os.Stderr, "配置无效:", err)
		os.Exit(1)
	}
	if dataDir == "" {
		dataDir = config.DefaultDataDir()
	}
	if dev {
		cfg.Server.OpenBrowser = false
		cfg.Demo.Enabled = true
		if cfg.Demo.Seed == 0 {
			cfg.Demo.Seed = 80
		}
	}
	if noOpen {
		cfg.Server.OpenBrowser = false
	}
	if noProxy {
		cfg.Proxy.Enabled = false
	}

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: parseLogLevel(cfg.Logging.Level),
	})))

	a, err := app.New(app.Options{
		Config:   cfg,
		DataDir:  dataDir,
		Dev:      dev,
		Headless: headless,
	})
	if err != nil {
		slog.Error("启动失败", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	if err := a.Run(ctx); err != nil {
		slog.Error("运行失败", "error", err)
		os.Exit(1)
	}
	slog.Info("已退出")
}

func parseLogLevel(value string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
