package event

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
)

type Event struct {
	V         int       `json:"v"`
	Type      string    `json:"type"`
	Seq       int64     `json:"seq"`
	TS        time.Time `json:"ts"`
	SessionID string    `json:"sessionId"`
	Data      any       `json:"data,omitempty"`
}

type Hub struct {
	mu        sync.RWMutex
	clients   map[*client]struct{}
	seq       atomic.Int64
	sessionID string
	closed    atomic.Bool
}

type client struct {
	conn      *websocket.Conn
	send      chan []byte
	done      chan struct{}
	closeOnce sync.Once
}

func NewHub(sessionID string) *Hub {
	return &Hub{
		clients:   make(map[*client]struct{}),
		sessionID: sessionID,
	}
}

func (h *Hub) Broadcast(eventType string, data any) {
	if h.closed.Load() {
		return
	}
	ev := Event{
		V:         1,
		Type:      eventType,
		Seq:       h.seq.Add(1),
		TS:        time.Now(),
		SessionID: h.sessionID,
		Data:      data,
	}
	payload, err := json.Marshal(ev)
	if err != nil {
		slog.Error("序列化事件失败", "type", eventType, "error", err)
		return
	}

	h.mu.RLock()
	defer h.mu.RUnlock()
	for c := range h.clients {
		select {
		case c.send <- payload:
		default:
			// 慢客户端：丢弃本事件，后续通过 REST 补齐。
		}
	}
}

func (h *Hub) Handle(w http.ResponseWriter, r *http.Request) {
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		slog.Debug("WebSocket 握手失败", "error", err)
		return
	}
	conn.SetReadLimit(1 << 20)

	c := &client{
		conn: conn,
		send: make(chan []byte, 256),
		done: make(chan struct{}),
	}

	h.mu.Lock()
	h.clients[c] = struct{}{}
	h.mu.Unlock()

	go c.writeLoop()

	for {
		if _, _, err := conn.Read(r.Context()); err != nil {
			break
		}
	}

	h.remove(c)
	c.shutdown()
}

func (h *Hub) ClientCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}

func (h *Hub) Close() {
	if !h.closed.CompareAndSwap(false, true) {
		return
	}
	h.mu.Lock()
	clients := make([]*client, 0, len(h.clients))
	for c := range h.clients {
		clients = append(clients, c)
	}
	h.clients = make(map[*client]struct{})
	h.mu.Unlock()

	for _, c := range clients {
		c.shutdown()
	}
}

func (h *Hub) remove(c *client) {
	h.mu.Lock()
	delete(h.clients, c)
	h.mu.Unlock()
}

func (c *client) writeLoop() {
	ticker := time.NewTicker(25 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case payload := <-c.send:
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			err := c.conn.Write(ctx, websocket.MessageText, payload)
			cancel()
			if err != nil {
				c.shutdown()
				return
			}
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			err := c.conn.Ping(ctx)
			cancel()
			if err != nil {
				c.shutdown()
				return
			}
		case <-c.done:
			return
		}
	}
}

func (c *client) shutdown() {
	c.closeOnce.Do(func() {
		close(c.done)
		_ = c.conn.Close(websocket.StatusNormalClosure, "bye")
	})
}
