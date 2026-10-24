//go:build windows

package hook

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// allocRemote 为远程线程参数分配内存。注入 WOW64 目标时必须保证地址低于 4GB，
// 否则 32 位远程线程无法访问该路径字符串。
func allocRemote(handle windows.Handle, size uintptr, wow64 bool) (uintptr, error) {
	flags := uintptr(memCommit | memReserve)
	if !wow64 {
		addr, _, callErr := procVirtualAllocEx.Call(uintptr(handle), 0, size, flags, uintptr(pageRW))
		if addr == 0 {
			return 0, fmt.Errorf("VirtualAllocEx 失败: %v", callErr)
		}
		return addr, nil
	}

	// 先尝试常见的低地址；VirtualAllocEx 在 WOW64 目标中可能默认返回 4GB 以上。
	candidates := []uintptr{0x10000000, 0x20000000, 0x30000000, 0x40000000, 0x50000000, 0}
	var lastErr error
	for _, base := range candidates {
		addr, _, callErr := procVirtualAllocEx.Call(uintptr(handle), base, size, flags, uintptr(pageRW))
		if addr == 0 {
			lastErr = callErr
			continue
		}
		if addr <= 0xFFFFFFFF {
			return addr, nil
		}
		_, _, _ = procVirtualFreeEx.Call(uintptr(handle), addr, 0, uintptr(memRelease))
		lastErr = fmt.Errorf("分配地址超过 4GB: 0x%X", addr)
	}
	return 0, fmt.Errorf("无法在 32 位目标中分配远程内存: %v", lastErr)
}

// loadLibraryAddress 返回目标进程中可执行的 LoadLibraryW 地址。
// x64 目标直接使用本进程 kernel32 的地址；WOW64 目标需要解析 32 位 kernel32
// 的导出 RVA，再加上目标进程内 kernel32/kernelbase 的模块基址。
func loadLibraryAddress(pid int, wow64 bool) (uintptr, error) {
	if !wow64 {
		return procLoadLibraryW.Addr(), nil
	}
	module, rva, err := loadLibraryExport32()
	if err != nil {
		return 0, err
	}
	base, ok := moduleBase(pid, module)
	if !ok {
		return 0, fmt.Errorf("目标进程未加载 %s", module)
	}
	addr := base + uintptr(rva)
	if addr > 0xFFFFFFFF {
		return 0, fmt.Errorf("32 位 LoadLibraryW 地址越界: 0x%X", addr)
	}
	return addr, nil
}

func moduleBase(pid int, name string) (uintptr, bool) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPMODULE|windows.TH32CS_SNAPMODULE32, uint32(pid))
	if err != nil {
		return 0, false
	}
	defer windows.CloseHandle(snapshot)

	entry := windows.ModuleEntry32{Size: uint32(unsafe.Sizeof(windows.ModuleEntry32{}))}
	if err := windows.Module32First(snapshot, &entry); err != nil {
		return 0, false
	}
	for {
		if strings.EqualFold(windows.UTF16ToString(entry.Module[:]), name) {
			return entry.ModBaseAddr, true
		}
		entry.Size = uint32(unsafe.Sizeof(windows.ModuleEntry32{}))
		if err := windows.Module32Next(snapshot, &entry); err != nil {
			break
		}
	}
	return 0, false
}

// loadLibraryExport32 解析 SysWOW64\kernel32.dll 的 LoadLibraryW 导出，
// 返回包含实际代码的模块名与 RVA（处理转发导出）。
func loadLibraryExport32() (string, uint32, error) {
	sysRoot := strings.TrimSpace(os.Getenv("SystemRoot"))
	if sysRoot == "" {
		sysRoot = `C:\Windows`
	}
	kernel32 := filepath.Join(sysRoot, "SysWOW64", "kernel32.dll")
	rva, forward, err := exportRVA(kernel32, "LoadLibraryW")
	if err != nil {
		return "", 0, err
	}
	if forward == "" {
		return "kernel32.dll", rva, nil
	}
	idx := strings.LastIndex(forward, ".")
	if idx <= 0 || idx == len(forward)-1 {
		return "", 0, fmt.Errorf("无法解析 LoadLibraryW 转发导出: %s", forward)
	}
	module := strings.TrimSuffix(forward[:idx], ".dll")
	function := forward[idx+1:]
	path := filepath.Join(filepath.Dir(kernel32), module+".dll")
	rva, next, err := exportRVA(path, function)
	if err != nil {
		return "", 0, err
	}
	if next != "" {
		return "", 0, fmt.Errorf("LoadLibraryW 转发层级过深: %s -> %s", forward, next)
	}
	return module + ".dll", rva, nil
}

type peExportDirectory struct {
	Characteristics       uint32
	TimeDateStamp         uint32
	MajorVersion          uint16
	MinorVersion          uint16
	Name                  uint32
	Base                  uint32
	NumberOfFunctions     uint32
	NumberOfNames         uint32
	AddressOfFunctions    uint32
	AddressOfNames        uint32
	AddressOfNameOrdinals uint32
}

func exportRVA(path, function string) (uint32, string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, "", fmt.Errorf("读取 %s: %w", path, err)
	}
	file, err := pe.NewFile(bytes.NewReader(raw))
	if err != nil {
		return 0, "", fmt.Errorf("解析 %s: %w", path, err)
	}
	defer file.Close()

	var directories []pe.DataDirectory
	switch header := file.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		directories = header.DataDirectory[:]
	case *pe.OptionalHeader64:
		directories = header.DataDirectory[:]
	default:
		return 0, "", fmt.Errorf("%s 的 PE 可选头无效", path)
	}
	if len(directories) <= pe.IMAGE_DIRECTORY_ENTRY_EXPORT {
		return 0, "", fmt.Errorf("%s 没有导出目录", path)
	}
	exportDir := directories[pe.IMAGE_DIRECTORY_ENTRY_EXPORT]
	if exportDir.VirtualAddress == 0 || exportDir.Size == 0 {
		return 0, "", fmt.Errorf("%s 没有导出表", path)
	}

	dirOffset, ok := peRVAToOffset(file, exportDir.VirtualAddress)
	if !ok || int(dirOffset)+40 > len(raw) {
		return 0, "", fmt.Errorf("%s 导出目录偏移无效", path)
	}
	dir := peExportDirectory{
		Characteristics:       binary.LittleEndian.Uint32(raw[dirOffset:]),
		TimeDateStamp:         binary.LittleEndian.Uint32(raw[dirOffset+4:]),
		MajorVersion:          binary.LittleEndian.Uint16(raw[dirOffset+8:]),
		MinorVersion:          binary.LittleEndian.Uint16(raw[dirOffset+10:]),
		Name:                  binary.LittleEndian.Uint32(raw[dirOffset+12:]),
		Base:                  binary.LittleEndian.Uint32(raw[dirOffset+16:]),
		NumberOfFunctions:     binary.LittleEndian.Uint32(raw[dirOffset+20:]),
		NumberOfNames:         binary.LittleEndian.Uint32(raw[dirOffset+24:]),
		AddressOfFunctions:    binary.LittleEndian.Uint32(raw[dirOffset+28:]),
		AddressOfNames:        binary.LittleEndian.Uint32(raw[dirOffset+32:]),
		AddressOfNameOrdinals: binary.LittleEndian.Uint32(raw[dirOffset+36:]),
	}
	funcsOffset, ok := peRVAToOffset(file, dir.AddressOfFunctions)
	if !ok {
		return 0, "", fmt.Errorf("%s 导出函数表偏移无效", path)
	}
	namesOffset, ok := peRVAToOffset(file, dir.AddressOfNames)
	if !ok {
		return 0, "", fmt.Errorf("%s 导出名称表偏移无效", path)
	}
	ordinalsOffset, ok := peRVAToOffset(file, dir.AddressOfNameOrdinals)
	if !ok {
		return 0, "", fmt.Errorf("%s 导出序号表偏移无效", path)
	}

	for i := uint32(0); i < dir.NumberOfNames; i++ {
		namePos := int(namesOffset) + int(i)*4
		ordinalPos := int(ordinalsOffset) + int(i)*2
		if namePos+4 > len(raw) || ordinalPos+2 > len(raw) {
			break
		}
		nameRVA := binary.LittleEndian.Uint32(raw[namePos:])
		nameOffset, ok := peRVAToOffset(file, nameRVA)
		if !ok || int(nameOffset) >= len(raw) {
			continue
		}
		end := bytes.IndexByte(raw[nameOffset:], 0)
		if end < 0 {
			continue
		}
		if !strings.EqualFold(string(raw[nameOffset:int(nameOffset)+end]), function) {
			continue
		}
		ordinal := binary.LittleEndian.Uint16(raw[ordinalPos:])
		if uint32(ordinal) >= dir.NumberOfFunctions {
			return 0, "", fmt.Errorf("%s 的 %s 序号越界", path, function)
		}
		funcPos := int(funcsOffset) + int(ordinal)*4
		if funcPos+4 > len(raw) {
			return 0, "", fmt.Errorf("%s 的导出函数表越界", path)
		}
		rva := binary.LittleEndian.Uint32(raw[funcPos:])
		if rva >= exportDir.VirtualAddress && rva < exportDir.VirtualAddress+exportDir.Size {
			forwardOffset, ok := peRVAToOffset(file, rva)
			if !ok || int(forwardOffset) >= len(raw) {
				return 0, "", fmt.Errorf("%s 的 %s 转发偏移无效", path, function)
			}
			forwardEnd := bytes.IndexByte(raw[forwardOffset:], 0)
			if forwardEnd < 0 {
				return 0, "", fmt.Errorf("%s 的 %s 转发字符串无效", path, function)
			}
			return 0, string(raw[forwardOffset : int(forwardOffset)+forwardEnd]), nil
		}
		return rva, "", nil
	}
	return 0, "", fmt.Errorf("%s 中未找到导出 %s", path, function)
}

func peRVAToOffset(file *pe.File, rva uint32) (uint32, bool) {
	for _, section := range file.Sections {
		if rva >= section.VirtualAddress && rva < section.VirtualAddress+section.Size {
			return rva - section.VirtualAddress + section.Offset, true
		}
	}
	return 0, false
}
