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
	// 服务端进程没有前台窗口，直接 ShowDialog 时对话框可能落在浏览器或其他应用后面，
	// 表现为接口一直挂起。这里在对话框显示后用定时器把它强制置顶并激活。
	script := `[Console]::OutputEncoding=[System.Text.Encoding]::UTF8
Add-Type -AssemblyName System.Windows.Forms | Out-Null
Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class ScanningPickFileTopMost {
  public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);
  [DllImport("user32.dll")] static extern bool EnumWindows(EnumWindowsProc cb, IntPtr p);
  [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetWindowText(IntPtr h, StringBuilder s, int c);
  [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] static extern bool SetWindowPos(IntPtr h, IntPtr after, int x, int y, int cx, int cy, uint flags);
  [DllImport("user32.dll")] static extern bool SetForegroundWindow(IntPtr h);
  public static bool Raise(string title) {
    uint me = (uint)System.Diagnostics.Process.GetCurrentProcess().Id;
    IntPtr found = IntPtr.Zero;
    EnumWindows((h, l) => {
      uint p; GetWindowThreadProcessId(h, out p);
      if (p != me) return true;
      var sb = new StringBuilder(512); GetWindowText(h, sb, sb.Capacity);
      if (sb.ToString() == title) { found = h; return false; }
      return true;
    }, IntPtr.Zero);
    if (found == IntPtr.Zero) return false;
    SetWindowPos(found, new IntPtr(-1), 0, 0, 0, 0, 0x43);
    SetForegroundWindow(found);
    return true;
  }
}
'@
$owner = New-Object System.Windows.Forms.Form
$owner.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::None
$owner.StartPosition = [System.Windows.Forms.FormStartPosition]::Manual
$owner.Location = New-Object System.Drawing.Point(-32000, -32000)
$owner.Size = New-Object System.Drawing.Size(1, 1)
$owner.ShowInTaskbar = $false
$owner.Show()
$dialog = New-Object System.Windows.Forms.OpenFileDialog
$dialog.Title = '选择要启动的桌面应用'
$dialog.Filter = '可执行文件 (*.exe)|*.exe|所有文件 (*.*)|*.*'
$global:scanningPickTicks = 0
$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 250
$timer.Add_Tick({
  $global:scanningPickTicks++
  [ScanningPickFileTopMost]::Raise('选择要启动的桌面应用') | Out-Null
  if ($global:scanningPickTicks -ge 20) { $timer.Stop() }
})
$timer.Start()
if ($dialog.ShowDialog($owner) -eq [System.Windows.Forms.DialogResult]::OK) { Write-Output $dialog.FileName }
$timer.Stop()
$owner.Close()`
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
