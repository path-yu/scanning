// Package eapi 解码网易云音乐桌面端的 EAPI 加密正文。
//
// EAPI 请求体为 params=<hex(AES-128-ECB(明文))>，响应体为原始
// AES-128-ECB 密文。解密后请求是 "/api/...-36cd479b6b5-{json}"，
// 响应是 JSON。该解码只用于把已抓到的 Flow 展示为可读内容，
// 不改变实际转发、重放或原始正文存储。
package eapi

import (
	"bytes"
	"crypto/aes"
	"encoding/hex"
	"strings"
)

const key = "e82ckenh8dichen8"

// IsEAPI 判断 Flow 是否属于网易云 EAPI 加密接口。
func IsEAPI(host, path string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host != "music.163.com" && !strings.HasSuffix(host, ".music.163.com") {
		return false
	}
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(path)), "/eapi/")
}

// DecryptResponse 尝试解密 EAPI 响应体，成功时返回 JSON 字节。
func DecryptResponse(data []byte) ([]byte, bool) {
	plain, ok := decryptECB(data)
	if !ok {
		return nil, false
	}
	plain = bytes.TrimSpace(plain)
	if len(plain) == 0 {
		return nil, false
	}
	switch plain[0] {
	case '{', '[':
		return plain, true
	default:
		return nil, false
	}
}

// DecryptRequest 尝试解析并解密 EAPI 请求体中的 params 字段，
// 返回其中的 JSON 部分。
func DecryptRequest(data []byte) ([]byte, bool) {
	text := strings.TrimSpace(string(data))
	index := strings.Index(text, "params=")
	if index < 0 {
		return nil, false
	}
	payload := text[index+len("params="):]
	if end := strings.IndexAny(payload, "&\r\n"); end >= 0 {
		payload = payload[:end]
	}
	payload = strings.TrimSpace(payload)
	if payload == "" || len(payload)%2 != 0 {
		return nil, false
	}
	raw, err := hex.DecodeString(payload)
	if err != nil {
		return nil, false
	}
	plain, ok := decryptECB(raw)
	if !ok {
		return nil, false
	}
	// 明文格式：/api/v6/playlist/detail-36cd479b6b5-{"id":"..."}
	for i, b := range plain {
		if b == '{' || b == '[' {
			return plain[i:], true
		}
	}
	return nil, false
}

func decryptECB(data []byte) ([]byte, bool) {
	if len(data) == 0 || len(data)%aes.BlockSize != 0 {
		return nil, false
	}
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, false
	}
	out := make([]byte, len(data))
	for i := 0; i < len(data); i += aes.BlockSize {
		block.Decrypt(out[i:i+aes.BlockSize], data[i:i+aes.BlockSize])
	}
	return pkcs7Unpad(out)
}

func pkcs7Unpad(data []byte) ([]byte, bool) {
	if len(data) == 0 {
		return nil, false
	}
	padding := int(data[len(data)-1])
	if padding <= 0 || padding > aes.BlockSize || padding > len(data) {
		return nil, false
	}
	for _, b := range data[len(data)-padding:] {
		if int(b) != padding {
			return nil, false
		}
	}
	return data[:len(data)-padding], true
}
