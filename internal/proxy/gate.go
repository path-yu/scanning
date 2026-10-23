package proxy

import (
	"context"
	"sync"
	"time"

	"scanning/internal/flow"
)

const (
	ResumeForward = "forward"
	ResumeAbort   = "abort"
	ResumeMock    = "mock"
)

// ResumeCommand 是断点放行时由前端提交的指令。
type ResumeCommand struct {
	Action  string        `json:"action"`
	Status  int           `json:"status,omitempty"`
	Headers []flow.Header `json:"headers,omitempty"`
	Body    *string       `json:"body,omitempty"`
	Method  string        `json:"method,omitempty"`
	Path    string        `json:"path,omitempty"`
}

type Gate struct {
	mu      sync.Mutex
	waiters map[string]chan ResumeCommand
}

func NewGate() *Gate {
	return &Gate{waiters: make(map[string]chan ResumeCommand)}
}

// Pause 注册断点并阻塞等待放行、超时或客户端断开。
// onPause 在 waiter 注册完成后调用，用于广播 flow.paused，避免竞态。
func (g *Gate) Pause(ctx context.Context, id string, timeout time.Duration, onPause func()) ResumeCommand {
	ch := make(chan ResumeCommand, 1)
	g.mu.Lock()
	g.waiters[id] = ch
	g.mu.Unlock()

	defer func() {
		g.mu.Lock()
		delete(g.waiters, id)
		g.mu.Unlock()
	}()

	if onPause != nil {
		onPause()
	}
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case cmd := <-ch:
		return normalizeResume(cmd)
	case <-timer.C:
		return ResumeCommand{Action: ResumeForward}
	case <-ctx.Done():
		return ResumeCommand{Action: ResumeAbort}
	}
}

func (g *Gate) Resume(id string, cmd ResumeCommand) bool {
	g.mu.Lock()
	ch, ok := g.waiters[id]
	g.mu.Unlock()
	if !ok {
		return false
	}
	select {
	case ch <- normalizeResume(cmd):
		return true
	default:
		return false
	}
}

func (g *Gate) Pending() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]string, 0, len(g.waiters))
	for id := range g.waiters {
		out = append(out, id)
	}
	return out
}

// ReleaseAll 向所有等待中的断点发送中止指令，用于代理停止时避免请求悬挂。
func (g *Gate) ReleaseAll(cmd ResumeCommand) {
	g.mu.Lock()
	channels := make([]chan ResumeCommand, 0, len(g.waiters))
	for _, ch := range g.waiters {
		channels = append(channels, ch)
	}
	g.mu.Unlock()

	for _, ch := range channels {
		select {
		case ch <- normalizeResume(cmd):
		default:
		}
	}
}

func normalizeResume(cmd ResumeCommand) ResumeCommand {
	switch cmd.Action {
	case ResumeAbort, ResumeMock:
	default:
		cmd.Action = ResumeForward
	}
	if cmd.Status < 100 || cmd.Status > 599 {
		cmd.Status = 0
	}
	return cmd
}
