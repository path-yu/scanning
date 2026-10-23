package proxy

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// ServeTransparent 处理一条透明代理连接：conn 已经完成 TLS 终止（HTTPS）或为原始明文连接（HTTP）。
func (e *Engine) ServeTransparent(conn net.Conn, host string, port int, scheme string) {
	if conn == nil {
		return
	}
	done := make(chan struct{})
	wrapped := &notifyConn{Conn: conn, done: done}
	listener := &singleConnListener{conn: wrapped, done: done}
	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			targetHost := host
			targetPort := port
			if scheme == "http" {
				h, p := splitHostPortDefault(r.Host, "80")
				if h != "" {
					targetHost = h
				}
				targetPort = parsePort(p, 80)
			}
			if targetHost == "" {
				http.Error(w, "透明代理缺少目标主机", http.StatusBadRequest)
				return
			}
			e.forward(w, r, scheme, targetHost, targetPort)
		}),
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       90 * time.Second,
	}
	_ = server.Serve(listener)
	_ = server.Close()
}

type notifyConn struct {
	net.Conn
	once sync.Once
	done chan struct{}
}

func (c *notifyConn) Close() error {
	c.once.Do(func() { close(c.done) })
	return c.Conn.Close()
}

type singleConnListener struct {
	conn   net.Conn
	done   chan struct{}
	served bool
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	if !l.served {
		l.served = true
		return l.conn, nil
	}
	<-l.done
	return nil, net.ErrClosed
}

func (l *singleConnListener) Close() error {
	select {
	case <-l.done:
	default:
		close(l.done)
	}
	return nil
}

func (l *singleConnListener) Addr() net.Addr {
	return l.conn.LocalAddr()
}
