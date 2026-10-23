// Package browser 负责启动一个使用独立配置目录、强制走本机代理的浏览器窗口。
package browser

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

const defaultURL = "https://example.com"

type Options struct {
	ProxyAddr string // 本机代理地址，例如 127.0.0.1:8899
	DataDir   string // Scanning 数据目录，用于存放独立浏览器配置
	URL       string // 启动后打开的地址，留空使用默认地址
	Preferred string // edge / chrome / chromium，留空自动选择
}

type Result struct {
	Browser    string `json:"browser"`
	Executable string `json:"executable"`
	ProfileDir string `json:"profileDir"`
	URL        string `json:"url"`
}

type candidate struct {
	name string
	path string
}

// Launch 启动浏览器后立即返回，不等待浏览器退出。
func Launch(opts Options) (Result, error) {
	proxyAddr := strings.TrimSpace(opts.ProxyAddr)
	if proxyAddr == "" {
		return Result{}, errors.New("代理地址为空")
	}
	target, err := NormalizeURL(opts.URL)
	if err != nil {
		return Result{}, err
	}
	executable, name, err := findExecutable(opts.Preferred)
	if err != nil {
		return Result{}, err
	}
	profileDir := filepath.Join(opts.DataDir, "browser-profile")
	if err := os.MkdirAll(profileDir, 0o700); err != nil {
		return Result{}, fmt.Errorf("创建浏览器配置目录: %w", err)
	}

	cmd := exec.Command(executable, BuildArgs(proxyAddr, profileDir, target)...)
	if err := cmd.Start(); err != nil {
		return Result{}, fmt.Errorf("启动 %s 失败: %w", name, err)
	}
	// 不等待浏览器退出，释放进程句柄即可。
	_ = cmd.Process.Release()

	return Result{
		Browser:    name,
		Executable: executable,
		ProfileDir: profileDir,
		URL:        target,
	}, nil
}

// NormalizeURL 校验并补全浏览器启动地址，只允许 http/https。
func NormalizeURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		raw = defaultURL
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("URL 无效: %w", err)
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
	default:
		return "", errors.New("只支持 http/https 地址")
	}
	if u.Hostname() == "" {
		return "", errors.New("URL 缺少主机")
	}
	return u.String(), nil
}

// BuildArgs 生成 Chromium 系浏览器的启动参数：独立配置 + 强制代理。
func BuildArgs(proxyAddr, profileDir, target string) []string {
	return []string{
		"--proxy-server=http://" + proxyAddr,
		"--user-data-dir=" + profileDir,
		"--no-first-run",
		"--no-default-browser-check",
		target,
	}
}

func findExecutable(preferred string) (string, string, error) {
	preferred = strings.ToLower(strings.TrimSpace(preferred))
	if preferred != "" && preferred != "edge" && preferred != "chrome" && preferred != "chromium" {
		return "", "", fmt.Errorf("不支持的浏览器类型 %q", preferred)
	}
	for _, item := range executableCandidates() {
		if preferred != "" && item.name != preferred {
			continue
		}
		path, ok := resolveExecutable(item.path)
		if ok {
			return path, item.name, nil
		}
	}
	return "", "", errors.New("未找到 Edge、Chrome 或 Chromium，请先安装其中任意一个")
}

func resolveExecutable(path string) (string, bool) {
	if path == "" {
		return "", false
	}
	if strings.ContainsAny(path, `/\`) {
		info, err := os.Stat(path)
		if err != nil || info.IsDir() {
			return "", false
		}
		return path, true
	}
	resolved, err := exec.LookPath(path)
	if err != nil {
		return "", false
	}
	return resolved, true
}

func executableCandidates() []candidate {
	switch runtime.GOOS {
	case "windows":
		var out []candidate
		add := func(name, base string, parts ...string) {
			if strings.TrimSpace(base) == "" {
				return
			}
			out = append(out, candidate{name: name, path: filepath.Join(append([]string{base}, parts...)...)})
		}
		edgeParts := []string{"Microsoft", "Edge", "Application", "msedge.exe"}
		add("edge", os.Getenv("ProgramFiles(x86)"), edgeParts...)
		add("edge", os.Getenv("ProgramFiles"), edgeParts...)
		chromeParts := []string{"Google", "Chrome", "Application", "chrome.exe"}
		add("chrome", os.Getenv("ProgramFiles"), chromeParts...)
		add("chrome", os.Getenv("ProgramFiles(x86)"), chromeParts...)
		add("chrome", os.Getenv("LOCALAPPDATA"), chromeParts...)
		return out
	case "darwin":
		return []candidate{
			{name: "edge", path: "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"},
			{name: "chrome", path: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"},
			{name: "chromium", path: "/Applications/Chromium.app/Contents/MacOS/Chromium"},
		}
	default:
		return []candidate{
			{name: "chrome", path: "google-chrome"},
			{name: "chrome", path: "google-chrome-stable"},
			{name: "chromium", path: "chromium"},
			{name: "chromium", path: "chromium-browser"},
			{name: "edge", path: "microsoft-edge"},
			{name: "edge", path: "microsoft-edge-stable"},
		}
	}
}
