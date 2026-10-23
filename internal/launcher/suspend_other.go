//go:build !windows

package launcher

import "os/exec"

const suspendedStartSupported = false

func configureSuspended(_ *exec.Cmd) {}

func resumeProcess(_ int) error { return nil }
