//go:build !windows && !linux

package procinfo

func lookupProcess(string, int, int) (Info, bool) {
	return Info{}, false
}

func processIDsByPath(string) []int { return nil }

func connectionsForPIDs([]int) []Connection { return nil }
