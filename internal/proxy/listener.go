package proxy

import (
	"bufio"
	"net"
	"sync"
)

type connListener struct {
	ch     chan net.Conn
	done   chan struct{}
	addr   net.Addr
	mu     sync.Mutex
	closed bool
}

func newConnListener(addr net.Addr) *connListener {
	return &connListener{
		ch:   make(chan net.Conn, 1024),
		done: make(chan struct{}),
		addr: addr,
	}
}

func (l *connListener) Accept() (net.Conn, error) {
	select {
	case <-l.done:
		return nil, net.ErrClosed
	case conn, ok := <-l.ch:
		if !ok {
			return nil, net.ErrClosed
		}
		return conn, nil
	}
}

func (l *connListener) Close() error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	close(l.done)
	l.mu.Unlock()

	for {
		select {
		case conn := <-l.ch:
			_ = conn.Close()
		default:
			return nil
		}
	}
}

func (l *connListener) Addr() net.Addr {
	return l.addr
}

func (l *connListener) Push(conn net.Conn) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		_ = conn.Close()
		return false
	}
	select {
	case l.ch <- conn:
		return true
	default:
		_ = conn.Close()
		return false
	}
}

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

type connSet struct {
	mu sync.Mutex
	m  map[net.Conn]struct{}
}

func (s *connSet) Add(conn net.Conn) {
	s.mu.Lock()
	s.m[conn] = struct{}{}
	s.mu.Unlock()
}

func (s *connSet) Remove(conn net.Conn) {
	s.mu.Lock()
	delete(s.m, conn)
	s.mu.Unlock()
}

func (s *connSet) CloseAll() {
	s.mu.Lock()
	conns := make([]net.Conn, 0, len(s.m))
	for conn := range s.m {
		conns = append(conns, conn)
	}
	s.m = make(map[net.Conn]struct{})
	s.mu.Unlock()

	for _, conn := range conns {
		_ = conn.Close()
	}
}
