//go:build windows

package hook

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	memCommit  = 0x00001000
	memReserve = 0x00002000
	memRelease = 0x00008000
	pageRW     = 0x00000004
)

var (
	procVirtualAllocEx     = windows.NewLazySystemDLL("kernel32.dll").NewProc("VirtualAllocEx")
	procVirtualFreeEx      = windows.NewLazySystemDLL("kernel32.dll").NewProc("VirtualFreeEx")
	procCreateRemoteThread = windows.NewLazySystemDLL("kernel32.dll").NewProc("CreateRemoteThread")
	procGetExitCodeThread  = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetExitCodeThread")
	procLoadLibraryW       = windows.NewLazySystemDLL("kernel32.dll").NewProc("LoadLibraryW")
)

func supported() bool { return true }

func injectPID(pid int, dllX64, dllX86 string) (string, bool, string, string, error) {
	if pid <= 0 {
		return "", false, "", "", fmt.Errorf("PID 无效")
	}
	if pid == os.Getpid() {
		return "", false, "", "", fmt.Errorf("不能注入 Scanning 自身")
	}
	access := uint32(windows.PROCESS_CREATE_THREAD |
		windows.PROCESS_VM_OPERATION |
		windows.PROCESS_VM_WRITE |
		windows.PROCESS_VM_READ |
		windows.PROCESS_QUERY_INFORMATION |
		windows.SYNCHRONIZE)
	handle, err := windows.OpenProcess(access, false, uint32(pid))
	if err != nil {
		return "", false, "", "", fmt.Errorf("打开进程失败（请以相同权限运行，必要时使用管理员）：%w", err)
	}
	defer windows.CloseHandle(handle)

	path := processPathFromHandle(handle)
	var wow64 bool
	if err := windows.IsWow64Process(handle, &wow64); err != nil {
		return path, false, "", "", fmt.Errorf("检测目标进程位数失败: %w", err)
	}
	arch := "x64"
	dllPath := dllX64
	if wow64 {
		arch = "x86"
		dllPath = dllX86
	}
	if strings.TrimSpace(dllPath) == "" {
		return path, false, arch, "", fmt.Errorf("未找到 %s Hook DLL，请先执行 make hook", arch)
	}
	if info, statErr := os.Stat(dllPath); statErr != nil {
		return path, false, arch, dllPath, fmt.Errorf("%s Hook DLL 不存在：%s: %w", arch, dllPath, statErr)
	} else if info.IsDir() {
		return path, false, arch, dllPath, fmt.Errorf("%s Hook DLL 路径是目录：%s", arch, dllPath)
	}

	dllName := filepath.Base(dllPath)
	if moduleLoaded(pid, dllName) {
		return path, true, arch, dllPath, nil
	}

	dllUTF16, err := windows.UTF16PtrFromString(dllPath)
	if err != nil {
		return path, false, arch, dllPath, fmt.Errorf("DLL 路径编码失败: %w", err)
	}
	dllLen := 0
	for p := unsafe.Pointer(dllUTF16); *(*uint16)(p) != 0; p = unsafe.Pointer(uintptr(p) + 2) {
		dllLen++
	}
	size := (dllLen + 1) * 2

	remote, allocErr := allocRemote(handle, uintptr(size), wow64)
	if allocErr != nil {
		return path, false, arch, dllPath, fmt.Errorf("远程内存分配失败: %w", allocErr)
	}
	defer procVirtualFreeEx.Call(uintptr(handle), remote, 0, uintptr(memRelease))

	var written uintptr
	if err := windows.WriteProcessMemory(handle, remote, (*byte)(unsafe.Pointer(dllUTF16)), uintptr(size), &written); err != nil {
		return path, false, arch, dllPath, fmt.Errorf("写入远程内存失败: %w", err)
	}

	startAddr, addrErr := loadLibraryAddress(pid, wow64)
	if addrErr != nil {
		return path, false, arch, dllPath, fmt.Errorf("解析 LoadLibraryW 地址失败: %w", addrErr)
	}
	thread, _, callErr := procCreateRemoteThread.Call(
		uintptr(handle),
		0,
		0,
		startAddr,
		remote,
		0,
		0,
	)
	if thread == 0 {
		return path, false, arch, dllPath, fmt.Errorf("CreateRemoteThread 失败（可能被安全软件拦截）：%v", callErr)
	}
	threadHandle := windows.Handle(thread)
	defer windows.CloseHandle(threadHandle)

	event, waitErr := windows.WaitForSingleObject(threadHandle, 8000)
	if waitErr != nil {
		return path, false, arch, dllPath, fmt.Errorf("等待注入线程失败: %w", waitErr)
	}
	if event == 258 { // WAIT_TIMEOUT
		// 线程未退出时 DLL 可能仍已加载，给一次验证机会。
		if moduleLoaded(pid, dllName) {
			return path, false, arch, dllPath, nil
		}
		return path, false, arch, dllPath, fmt.Errorf("注入线程 8 秒未返回")
	}
	var exitCode uint32
	ret, _, callErr := procGetExitCodeThread.Call(uintptr(threadHandle), uintptr(unsafe.Pointer(&exitCode)))
	if ret == 0 {
		return path, false, arch, dllPath, fmt.Errorf("读取注入结果失败: %v", callErr)
	}
	if exitCode == 0 {
		return path, false, arch, dllPath, fmt.Errorf("LoadLibraryW 返回 0：可能被安全软件拦截、DLL 路径不可访问或架构不匹配")
	}
	// 模块列表的更新可能略晚于 LoadLibraryW 返回，短暂重试避免误报注入失败。
	for attempt := 0; attempt < 10 && !moduleLoaded(pid, dllName); attempt++ {
		time.Sleep(50 * time.Millisecond)
	}
	if !moduleLoaded(pid, dllName) {
		return path, false, arch, dllPath, fmt.Errorf("LoadLibrary 返回成功，但进程模块列表中未找到 %s", dllName)
	}
	return path, false, arch, dllPath, nil
}

func processByPID(pid int) (Process, bool) {
	if pid <= 0 {
		return Process{}, false
	}
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return Process{}, false
	}
	defer windows.CloseHandle(handle)
	path := processPathFromHandle(handle)
	name := filepath.Base(path)
	if name == "." || name == "" {
		name = fmt.Sprintf("PID %d", pid)
	}
	return Process{PID: pid, Name: name, Path: path}, true
}

func listProcesses(name string) []Process {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil
	}
	defer windows.CloseHandle(snapshot)
	entry := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	if err := windows.Process32First(snapshot, &entry); err != nil {
		return nil
	}
	want := strings.ToLower(strings.TrimSpace(name))
	var out []Process
	for {
		exe := windows.UTF16ToString(entry.ExeFile[:])
		if want == "" || strings.EqualFold(exe, want) {
			pid := int(entry.ProcessID)
			if pid > 0 && pid != os.Getpid() {
				proc := Process{PID: pid, Name: exe}
				if handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, entry.ProcessID); err == nil {
					proc.Path = processPathFromHandle(handle)
					windows.CloseHandle(handle)
				}
				out = append(out, proc)
			}
		}
		entry.Size = uint32(unsafe.Sizeof(windows.ProcessEntry32{}))
		if err := windows.Process32Next(snapshot, &entry); err != nil {
			break
		}
	}
	return out
}

func moduleLoaded(pid int, moduleName string) bool {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPMODULE|windows.TH32CS_SNAPMODULE32, uint32(pid))
	if err != nil {
		return false
	}
	defer windows.CloseHandle(snapshot)
	entry := windows.ModuleEntry32{Size: uint32(unsafe.Sizeof(windows.ModuleEntry32{}))}
	if err := windows.Module32First(snapshot, &entry); err != nil {
		return false
	}
	for {
		if strings.EqualFold(windows.UTF16ToString(entry.Module[:]), moduleName) {
			return true
		}
		entry.Size = uint32(unsafe.Sizeof(windows.ModuleEntry32{}))
		if err := windows.Module32Next(snapshot, &entry); err != nil {
			break
		}
	}
	return false
}

func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	defer windows.CloseHandle(handle)
	var code uint32
	err = windows.GetExitCodeProcess(handle, &code)
	if err != nil {
		return false
	}
	return code == 259 // STILL_ACTIVE
}

func processPathFromHandle(handle windows.Handle) string {
	if handle == 0 {
		return ""
	}
	buf := make([]uint16, windows.MAX_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(handle, 0, &buf[0], &size); err != nil {
		return ""
	}
	return windows.UTF16ToString(buf[:size])
}

func pickInt(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
