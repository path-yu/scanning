// Package sysproxy 一键接管系统代理（Windows 为 HKCU Internet Settings），并支持备份与还原。
package sysproxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const backupFile = "proxy-backup.json"

type Config struct {
	ProxyEnable   int    `json:"proxyEnable"`
	ProxyServer   string `json:"proxyServer"`
	ProxyOverride string `json:"proxyOverride"`
	AutoConfigURL string `json:"autoConfigUrl"`
}

type Backup struct {
	Config
	AppliedProxy string    `json:"appliedProxy"`
	CreatedAt    time.Time `json:"createdAt"`
	Active       bool      `json:"active"`
}

type Status struct {
	Platform     string    `json:"platform"`
	Supported    bool      `json:"supported"`
	Current      Config    `json:"current"`
	Backup       *Backup   `json:"backup,omitempty"`
	Active       bool      `json:"active"`
	AppliedProxy string    `json:"appliedProxy,omitempty"`
	UpdatedAt    time.Time `json:"updatedAt"`
	Message      string    `json:"message,omitempty"`
}

type backend interface {
	platform() string
	supported() bool
	read() (Config, error)
	write(Config) error
	notify()
}

type Manager struct {
	mu         sync.Mutex
	backupPath string
	backend    backend
}

func NewManager(dataDir string) *Manager {
	return newManager(dataDir, newBackend())
}

func newManager(dataDir string, b backend) *Manager {
	return &Manager{
		backupPath: filepath.Join(dataDir, backupFile),
		backend:    b,
	}
}

func (m *Manager) Status() (Status, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.statusLocked()
}

// Apply 把系统代理接管为 proxyAddr，并备份原设置。
func (m *Manager) Apply(proxyAddr string) (Status, error) {
	proxyAddr = strings.TrimSpace(proxyAddr)
	if _, _, err := net.SplitHostPort(proxyAddr); err != nil {
		return Status{}, fmt.Errorf("代理地址无效: %w", err)
	}
	if !m.backend.supported() {
		return Status{}, errors.New("当前平台暂不支持一键接管系统代理")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	existing, err := m.loadBackup()
	if err != nil {
		return Status{}, err
	}
	if existing != nil && existing.Active {
		if existing.AppliedProxy == proxyAddr {
			return m.statusLocked()
		}
		return Status{}, errors.New("系统代理已被接管，请先还原后再重新接管")
	}

	current, err := m.backend.read()
	if err != nil {
		return Status{}, err
	}
	backup := &Backup{
		Config:       current,
		AppliedProxy: proxyAddr,
		CreatedAt:    time.Now(),
		Active:       true,
	}
	if err := m.saveBackup(backup); err != nil {
		return Status{}, err
	}

	next := current
	next.ProxyEnable = 1
	next.ProxyServer = proxyAddr
	next.ProxyOverride = mergeOverride(current.ProxyOverride)
	next.AutoConfigURL = ""
	if err := m.backend.write(next); err != nil {
		// 回滚原设置，避免留下半接管状态。
		_ = m.backend.write(current)
		m.backend.notify()
		backup.Active = false
		_ = m.saveBackup(backup)
		return Status{}, fmt.Errorf("写入系统代理失败: %w", err)
	}
	m.backend.notify()
	return m.statusLocked()
}

// Restore 还原接管前的系统代理设置。
func (m *Manager) Restore() (Status, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	backup, err := m.loadBackup()
	if err != nil {
		return Status{}, err
	}
	if backup == nil || !backup.Active {
		return Status{}, errors.New("没有可还原的系统代理备份")
	}
	if err := m.backend.write(backup.Config); err != nil {
		return Status{}, fmt.Errorf("还原系统代理失败: %w", err)
	}
	m.backend.notify()
	backup.Active = false
	if err := m.saveBackup(backup); err != nil {
		return Status{}, err
	}
	return m.statusLocked()
}

// RestoreIfApplied 在程序退出时调用：仅当系统代理仍指向本工具时还原，
// 避免覆盖用户后来手动修改的设置。
func (m *Manager) RestoreIfApplied() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	backup, err := m.loadBackup()
	if err != nil || backup == nil || !backup.Active {
		return err
	}
	current, err := m.backend.read()
	if err != nil {
		return err
	}
	if current.ProxyEnable != 1 || current.ProxyServer != backup.AppliedProxy {
		return nil
	}
	if err := m.backend.write(backup.Config); err != nil {
		return err
	}
	m.backend.notify()
	backup.Active = false
	if err := m.saveBackup(backup); err != nil {
		return err
	}
	slog.Info("已自动还原系统代理", "proxy", backup.AppliedProxy)
	return nil
}

func (m *Manager) statusLocked() (Status, error) {
	status := Status{
		Platform:  m.backend.platform(),
		Supported: m.backend.supported(),
		UpdatedAt: time.Now(),
	}
	if !status.Supported {
		status.Message = "当前平台暂不支持一键接管系统代理，请手动设置系统代理"
		return status, nil
	}
	current, err := m.backend.read()
	if err != nil {
		return status, err
	}
	status.Current = current

	backup, err := m.loadBackup()
	if err != nil {
		return status, err
	}
	if backup != nil {
		status.Backup = backup
		status.Active = backup.Active
		if backup.Active {
			status.AppliedProxy = backup.AppliedProxy
			if current.ProxyEnable != 1 || current.ProxyServer != backup.AppliedProxy {
				status.Message = "系统代理当前已被其他程序修改，备份仍保留，可点击还原"
			} else {
				status.Message = "系统代理已接管为 " + backup.AppliedProxy
			}
		}
	}
	return status, nil
}

func mergeOverride(raw string) string {
	required := []string{"localhost", "127.*", "<local>"}
	seen := make(map[string]bool)
	out := make([]string, 0, len(required)+4)
	for _, item := range strings.Split(raw, ";") {
		item = strings.TrimSpace(item)
		if item == "" || seen[strings.ToLower(item)] {
			continue
		}
		seen[strings.ToLower(item)] = true
		out = append(out, item)
	}
	for _, item := range required {
		if !seen[strings.ToLower(item)] {
			out = append(out, item)
		}
	}
	return strings.Join(out, ";")
}

func (m *Manager) loadBackup() (*Backup, error) {
	data, err := os.ReadFile(m.backupPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("读取系统代理备份失败: %w", err)
	}
	var backup Backup
	if err := json.Unmarshal(data, &backup); err != nil {
		return nil, fmt.Errorf("解析系统代理备份失败: %w", err)
	}
	return &backup, nil
}

func (m *Manager) saveBackup(backup *Backup) error {
	data, err := json.MarshalIndent(backup, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化系统代理备份失败: %w", err)
	}
	tmp := m.backupPath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("写入系统代理备份失败: %w", err)
	}
	if err := os.Rename(tmp, m.backupPath); err != nil {
		return fmt.Errorf("替换系统代理备份失败: %w", err)
	}
	return nil
}
