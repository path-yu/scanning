//go:build windows

package hook

import (
	"fmt"
	"time"

	"golang.org/x/sys/windows"
)

const hookReadyEventPrefix = `Local\ScanningHookReady_`

// WaitReady 等待 Hook DLL 完成首次 IAT 扫描后发出的就绪事件。
// 超时返回错误，但调用方可忽略并继续启动目标进程。
func WaitReady(pid int, timeout time.Duration) error {
	if pid <= 0 {
		return fmt.Errorf("PID 无效")
	}
	name, err := windows.UTF16PtrFromString(fmt.Sprintf("%s%d", hookReadyEventPrefix, pid))
	if err != nil {
		return err
	}
	deadline := time.Now().Add(timeout)
	for {
		handle, openErr := windows.OpenEvent(windows.SYNCHRONIZE, false, name)
		if openErr == nil {
			// 成功打开后所有分支都会立即返回；显式关闭而不是 defer，
			// 避免以后改成 continue 时在循环中累积事件句柄。
			remaining := time.Until(deadline)
			if remaining <= 0 {
				_ = windows.CloseHandle(handle)
				return fmt.Errorf("等待 Hook 就绪超时")
			}
			milliseconds := uint32(remaining / time.Millisecond)
			if milliseconds == 0 {
				milliseconds = 1
			}
			event, waitErr := windows.WaitForSingleObject(handle, milliseconds)
			_ = windows.CloseHandle(handle)
			if waitErr != nil {
				return waitErr
			}
			if event != windows.WAIT_OBJECT_0 {
				return fmt.Errorf("等待 Hook 就绪超时")
			}
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("等待 Hook 就绪事件超时: %w", openErr)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
