//go:build !dev

package web

import "embed"

// Assets 是 Vite 构建产物，由生产二进制内嵌。
//
//go:embed all:dist
var Assets embed.FS

const Dev = false
