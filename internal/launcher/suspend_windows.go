//go:build windows

package launcher

import (
	"fmt"
	"os/exec"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	suspendedStartSupported = true
	createSuspended         = 0x00000004
	threadQueryInformation  = 0x0040
)

var procGetThreadTimes = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetThreadTimes")

// configureSuspended 让应用以挂起状态创建，便于在它执行任何网络代码前注入 Hook。
func configureSuspended(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.CreationFlags |= createSuspended
}

// resumeProcess 只恢复 CREATE_SUSPENDED 挂起的主线程。
// os/exec 不暴露 CreateProcess 返回的主线程句柄，因此从线程快照中按创建时间
// 选取最早的线程。线程 ID 并不按创建顺序分配，不能用最小 ID 判断主线程。
func resumeProcess(pid int) error {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return fmt.Errorf("枚举线程失败: %w", err)
	}
	defer windows.CloseHandle(snapshot)

	entry := windows.ThreadEntry32{Size: uint32(unsafe.Sizeof(windows.ThreadEntry32{}))}
	if err := windows.Thread32First(snapshot, &entry); err != nil {
		return fmt.Errorf("枚举线程失败: %w", err)
	}
	var mainThreadID uint32
	var mainCreated uint64
	found := false
	for {
		if entry.OwnerProcessID == uint32(pid) {
			thread, openErr := windows.OpenThread(threadQueryInformation|windows.THREAD_SUSPEND_RESUME, false, entry.ThreadID)
			if openErr == nil {
				if created, ok := threadCreationTime(thread); ok && (!found || created < mainCreated) {
					mainThreadID = entry.ThreadID
					mainCreated = created
					found = true
				}
				_ = windows.CloseHandle(thread)
			}
		}
		entry.Size = uint32(unsafe.Sizeof(windows.ThreadEntry32{}))
		if err := windows.Thread32Next(snapshot, &entry); err != nil {
			break
		}
	}
	if !found {
		return fmt.Errorf("未找到进程主线程")
	}

	thread, err := windows.OpenThread(windows.THREAD_SUSPEND_RESUME, false, mainThreadID)
	if err != nil {
		return fmt.Errorf("打开主线程失败: %w", err)
	}
	defer windows.CloseHandle(thread)
	if _, err := windows.ResumeThread(thread); err != nil {
		return fmt.Errorf("恢复主线程失败: %w", err)
	}
	return nil
}

func threadCreationTime(thread windows.Handle) (uint64, bool) {
	var creation, exit, kernel, user windows.Filetime
	ret, _, _ := procGetThreadTimes.Call(
		uintptr(thread),
		uintptr(unsafe.Pointer(&creation)),
		uintptr(unsafe.Pointer(&exit)),
		uintptr(unsafe.Pointer(&kernel)),
		uintptr(unsafe.Pointer(&user)),
	)
	if ret == 0 {
		return 0, false
	}
	return uint64(creation.HighDateTime)<<32 | uint64(creation.LowDateTime), true
}
