//go:build !windows && !linux

package procinfo

import "time"

func processStartTime(int) (time.Time, bool) { return time.Time{}, false }

func lookupProcess(string, int, int) (Info, bool) {
	return Info{}, false
}

func processIDsByPath(string) []int { return nil }

func connectionsForPIDs([]int) []Connection { return nil }
