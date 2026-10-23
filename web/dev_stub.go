//go:build dev

package web

import "embed"

// Assets 在 dev 构建下为空，前端由 Vite 开发服务器提供。
var Assets embed.FS

const Dev = true
