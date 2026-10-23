//go:build windows

package hook

import (
	"fmt"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestWaitReadySignalled(t *testing.T) {
	const pid = 999999
	name, err := windows.UTF16PtrFromString(fmt.Sprintf("%s%d", hookReadyEventPrefix, pid))
	if err != nil {
		t.Fatal(err)
	}
	event, err := windows.CreateEvent(nil, 1, 0, name)
	if err != nil {
		t.Fatalf("CreateEvent: %v", err)
	}
	defer windows.CloseHandle(event)
	if err := windows.SetEvent(event); err != nil {
		t.Fatalf("SetEvent: %v", err)
	}
	if err := WaitReady(pid, time.Second); err != nil {
		t.Fatalf("WaitReady: %v", err)
	}
}

func TestWaitReadyTimeout(t *testing.T) {
	if err := WaitReady(999998, 30*time.Millisecond); err == nil {
		t.Fatal("expected timeout error")
	}
}
