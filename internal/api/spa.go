package api

import (
	"io/fs"
	"net/http"
	"path"
	"strings"

	"scanning/web"
)

func (s *Server) handleSPA(w http.ResponseWriter, r *http.Request) {
	if s.opts.Headless {
		http.Error(w, "UI is disabled in headless mode", http.StatusNotFound)
		return
	}

	if web.Dev {
		if r.URL.Path == "/" || r.URL.Path == "/index.html" {
			s.ensureSessionCookie(w, r)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store")
			_, _ = w.Write([]byte(devLandingPage))
			return
		}
		http.NotFound(w, r)
		return
	}

	if s.webFS == nil {
		http.Error(w, "frontend assets are not embedded; run `npm run build` in web/ first", http.StatusInternalServerError)
		return
	}

	name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
	if name == "" || name == "." {
		name = "index.html"
	}

	info, err := fs.Stat(s.webFS, name)
	if err != nil || info.IsDir() {
		// 带扩展名但不存在，按静态资源 404；否则回退到 SPA 入口。
		if strings.Contains(path.Base(name), ".") {
			http.NotFound(w, r)
			return
		}
		name = "index.html"
	}

	if name == "index.html" {
		s.ensureSessionCookie(w, r)
		w.Header().Set("Cache-Control", "no-store, must-revalidate")
	} else if strings.HasPrefix(name, "assets/") {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	}

	http.ServeFileFS(w, r, s.webFS, name)
}

func (s *Server) ensureSessionCookie(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookieName); err == nil && constantEqual(cookie.Value, s.opts.Token) {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    s.opts.Token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

const devLandingPage = `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Scanning API</title>
  <style>
    body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0b0f14;color:#e6edf3;font:14px/1.6 system-ui,-apple-system,"Segoe UI",sans-serif}
    main{max-width:560px;padding:48px;border:1px solid #1f2937;border-radius:16px;background:#111821}
    h1{margin:0 0 12px;font-size:22px}
    p{color:#94a3b8}
    a{color:#38bdf8}
    code{background:#0b0f14;padding:2px 6px;border-radius:4px;color:#a5b4fc}
  </style>
</head>
<body>
  <main>
    <h1>Scanning API 已启动</h1>
    <p>当前是开发模式，前端由 Vite 提供。</p>
    <p>请打开 <a href="http://127.0.0.1:5173">http://127.0.0.1:5173</a></p>
    <p>API 健康检查：<code>GET /healthz</code></p>
  </main>
</body>
</html>
`
