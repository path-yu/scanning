package launcher

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

// PickFile 在服务端桌面弹出原生文件选择框，返回绝对路径；canceled 表示用户取消。
func PickFile(ctx context.Context) (path string, canceled bool, err error) {
	switch runtime.GOOS {
	case "windows":
		return pickFileWindows(ctx)
	case "darwin":
		return pickFileDarwin(ctx)
	default:
		return pickFileLinux(ctx)
	}
}

func pickFileWindows(ctx context.Context) (string, bool, error) {
	script := `[Console]::OutputEncoding=[System.Text.Encoding]::UTF8
Add-Type -AssemblyName System.Windows.Forms | Out-Null
$dialog = New-Object System.Windows.Forms.OpenFileDialog
$dialog.Title = '选择要启动的桌面应用'
$dialog.Filter = '可执行文件 (*.exe)|*.exe|所有文件 (*.*)|*.*'
if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { Write-Output $dialog.FileName }`
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-STA", "-Command", script)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return "", false, ctx.Err()
		}
		return "", false, fmt.Errorf("打开文件对话框失败: %v %s", err, strings.TrimSpace(stderr.String()))
	}
	path := strings.TrimSpace(strings.TrimRight(stdout.String(), "\r\n"))
	if path == "" {
		return "", true, nil
	}
	return path, false, nil
}

func pickFileDarwin(ctx context.Context) (string, bool, error) {
	script := `POSIX path of (choose file with prompt "选择要启动的桌面应用")`
	cmd := exec.CommandContext(ctx, "osascript", "-e", script)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		if ctx.Err() != nil {
			return "", false, ctx.Err()
		}
		message := stderr.String()
		if strings.Contains(message, "User canceled") || strings.Contains(message, "(-128)") {
			return "", true, nil
		}
		return "", false, fmt.Errorf("打开文件对话框失败: %v %s", err, strings.TrimSpace(message))
	}
	path := strings.TrimSpace(string(out))
	if path == "" {
		return "", true, nil
	}
	return path, false, nil
}

func pickFileLinux(ctx context.Context) (string, bool, error) {
	if binary, err := exec.LookPath("zenity"); err == nil {
		return runLinuxPicker(ctx, binary, "--file-selection", "--title=选择要启动的桌面应用")
	}
	if binary, err := exec.LookPath("kdialog"); err == nil {
		return runLinuxPicker(ctx, binary, "--getopenfilename", ".", "可执行文件")
	}
	return "", false, fmt.Errorf("当前环境没有 zenity/kdialog，请手动输入应用路径")
}

func runLinuxPicker(ctx context.Context, binary string, args ...string) (string, bool, error) {
	cmd := exec.CommandContext(ctx, binary, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		if ctx.Err() != nil {
			return "", false, ctx.Err()
		}
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			return "", true, nil
		}
		return "", false, fmt.Errorf("打开文件对话框失败: %v %s", err, strings.TrimSpace(stderr.String()))
	}
	path := strings.TrimSpace(string(out))
	if path == "" {
		return "", true, nil
	}
	return path, false, nil
}
