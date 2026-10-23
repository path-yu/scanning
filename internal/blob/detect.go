// Package blob 提供正文存储与文本/二进制判定。
package blob

import (
	"bytes"
	"unicode/utf8"
)

// LooksBinary 判断正文是否明显不是可读文本。
// 服务端 Content-Type 可能不可信：例如网易云 EAPI 接口返回 text/plain，
// 实际正文却是加密二进制。此时不能仅依赖 MIME 判断。
func LooksBinary(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	sample := data
	if len(sample) > 4096 {
		sample = sample[:4096]
	}
	if bytes.IndexByte(sample, 0) >= 0 {
		return true
	}

	control := 0
	for _, b := range sample {
		if b < 0x20 && b != '\t' && b != '\n' && b != '\r' {
			control++
		}
	}
	if control*20 > len(sample) {
		return true
	}

	if utf8.Valid(sample) {
		return false
	}
	invalid := 0
	for i := 0; i < len(sample); {
		r, size := utf8.DecodeRune(sample[i:])
		if r == utf8.RuneError && size == 1 {
			invalid++
		}
		i += size
	}
	return invalid*50 > len(sample)
}
