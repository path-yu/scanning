//go:build !windows

package hook

import "time"

func WaitReady(_ int, _ time.Duration) error { return nil }
