//go:build !windows

package hook

import "fmt"

func supported() bool { return false }

func injectPID(pid int, dllX64, dllX86 string) (string, bool, string, string, error) {
	return "", false, "", "", fmt.Errorf("进程注入目前仅支持 Windows")
}

func processByPID(pid int) (Process, bool) {
	return Process{}, false
}

func listProcesses(name string) []Process {
	return nil
}

func moduleLoaded(pid int, moduleName string) bool {
	return false
}

func processAlive(pid int) bool {
	return false
}
