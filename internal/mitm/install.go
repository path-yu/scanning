package mitm

import (
	"context"
	"crypto/x509"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type InstallResult struct {
	Installed bool     `json:"installed"`
	Message   string   `json:"message"`
	Commands  []string `json:"commands,omitempty"`
	Status    Status   `json:"status"`
}

func (c *Center) Install(ctx context.Context, target string) (InstallResult, error) {
	target = strings.ToLower(strings.TrimSpace(target))
	if target == "" {
		target = "user"
	}
	if target != "user" && target != "system" {
		return InstallResult{}, fmt.Errorf("target 必须是 user 或 system")
	}

	caPath := c.CAPath()
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		if target == "system" {
			cmd = exec.CommandContext(ctx, "certutil", "-addstore", "Root", caPath)
		} else {
			cmd = exec.CommandContext(ctx, "certutil", "-addstore", "-user", "Root", caPath)
		}
	case "darwin":
		if target == "system" {
			return InstallResult{
				Installed: c.Status().Installed,
				Message:   "系统级安装需要管理员权限，请手动执行下方命令",
				Commands:  manualCommands(caPath),
				Status:    c.Status(),
			}, nil
		}
		home, _ := os.UserHomeDir()
		keychain := filepath.Join(home, "Library", "Keychains", "login.keychain-db")
		cmd = exec.CommandContext(ctx, "security", "add-trusted-cert", "-r", "trustRoot", "-k", keychain, caPath)
	default:
		if target == "system" {
			return InstallResult{
				Installed: c.Status().Installed,
				Message:   "Linux 系统证书安装需要 sudo，请手动执行下方命令",
				Commands:  manualCommands(caPath),
				Status:    c.Status(),
			}, nil
		}
		certutil, err := exec.LookPath("certutil")
		if err != nil {
			return InstallResult{
				Installed: c.Status().Installed,
				Message:   "未找到 certutil，请手动把证书导入浏览器信任库",
				Commands:  manualCommands(caPath),
				Status:    c.Status(),
			}, nil
		}
		home, _ := os.UserHomeDir()
		nssDB := "sql:" + filepath.Join(home, ".pki", "nssdb")
		cmd = exec.CommandContext(ctx, certutil, "-d", nssDB, "-A", "-t", "C,,", "-n", "Scanning Root CA", "-i", caPath)
	}

	output, err := cmd.CombinedOutput()
	status := c.Status()
	if err != nil {
		msg := strings.TrimSpace(string(output))
		if msg == "" {
			msg = err.Error()
		}
		return InstallResult{
			Installed: status.Installed,
			Message:   "自动安装失败：" + msg,
			Commands:  manualCommands(caPath),
			Status:    status,
		}, nil
	}

	status = c.Status()
	msg := "证书已安装到"
	if target == "system" {
		msg += "系统根证书库"
	} else {
		msg += "当前用户根证书库"
	}
	return InstallResult{
		Installed: status.Installed,
		Message:   msg,
		Commands:  manualCommands(caPath),
		Status:    status,
	}, nil
}

func isInstalled(cert *x509.Certificate, caPath, thumb string) bool {
	switch runtime.GOOS {
	case "windows":
		if runQuiet("certutil", "-user", "-verifystore", "Root", thumb) {
			return true
		}
		return runQuiet("certutil", "-verifystore", "Root", thumb)
	case "darwin":
		fp := strings.ReplaceAll(fingerprintSHA256(cert.Raw), ":", "")
		home, _ := os.UserHomeDir()
		keychains := []string{
			filepath.Join(home, "Library", "Keychains", "login.keychain-db"),
			"/Library/Keychains/System.keychain",
		}
		for _, keychain := range keychains {
			out, err := exec.Command("security", "find-certificate", "-a", "-c", "Scanning Root CA", "-Z", keychain).Output()
			if err == nil && strings.Contains(strings.ToUpper(string(out)), fp) {
				return true
			}
		}
		return false
	default:
		if fileExists("/usr/local/share/ca-certificates/scanning.crt") {
			return true
		}
		home, _ := os.UserHomeDir()
		nssDB := filepath.Join(home, ".pki", "nssdb")
		return runQuiet("certutil", "-d", "sql:"+nssDB, "-L", "-n", "Scanning Root CA")
	}
}

func manualCommands(caPath string) []string {
	switch runtime.GOOS {
	case "windows":
		return []string{
			fmt.Sprintf(`certutil -addstore -user Root "%s"`, caPath),
			fmt.Sprintf(`certutil -addstore Root "%s"   # 管理员权限`, caPath),
		}
	case "darwin":
		home, _ := os.UserHomeDir()
		return []string{
			fmt.Sprintf(`security add-trusted-cert -r trustRoot -k "%s" "%s"`, filepath.Join(home, "Library", "Keychains", "login.keychain-db"), caPath),
			fmt.Sprintf(`sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "%s"`, caPath),
		}
	default:
		return []string{
			fmt.Sprintf(`sudo cp "%s" /usr/local/share/ca-certificates/scanning.crt`, caPath),
			"sudo update-ca-certificates",
			fmt.Sprintf(`certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n "Scanning Root CA" -i "%s"`, caPath),
		}
	}
}

func runQuiet(name string, args ...string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, name, args...).Run() == nil
}
