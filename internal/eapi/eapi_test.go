package eapi

import (
	"bytes"
	"crypto/aes"
	"encoding/hex"
	"strings"
	"testing"
)

func encryptECB(t *testing.T, plain []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		t.Fatal(err)
	}
	padding := aes.BlockSize - len(plain)%aes.BlockSize
	padded := append(append([]byte(nil), plain...), bytes.Repeat([]byte{byte(padding)}, padding)...)
	out := make([]byte, len(padded))
	for i := 0; i < len(padded); i += aes.BlockSize {
		block.Encrypt(out[i:i+aes.BlockSize], padded[i:i+aes.BlockSize])
	}
	return out
}

func TestIsEAPI(t *testing.T) {
	cases := []struct {
		host, path string
		want       bool
	}{
		{"interfacepc.music.163.com", "/eapi/v6/playlist/detail", true},
		{"music.163.com", "/eapi/song/enhance/player/url", true},
		{"interfacepc.music.163.com", "/api/v6/playlist/detail", false},
		{"example.com", "/eapi/v6/playlist/detail", false},
	}
	for _, tc := range cases {
		if got := IsEAPI(tc.host, tc.path); got != tc.want {
			t.Fatalf("IsEAPI(%q,%q)=%v, want %v", tc.host, tc.path, got, tc.want)
		}
	}
}

func TestDecryptResponse(t *testing.T) {
	plain := []byte(`{"code":200,"playlist":{"id":1,"name":"test"}}`)
	cipher := encryptECB(t, plain)
	got, ok := DecryptResponse(cipher)
	if !ok || !bytes.Equal(got, plain) {
		t.Fatalf("DecryptResponse=%q,%v want %q", got, ok, plain)
	}
}

func TestDecryptRequest(t *testing.T) {
	plain := []byte(`/api/v6/playlist/detail-36cd479b6b5-{"id":"697807559","n":"500"}`)
	cipher := encryptECB(t, plain)
	body := []byte("params=" + strings.ToUpper(hex.EncodeToString(cipher)) + "&x=1")
	got, ok := DecryptRequest(body)
	want := []byte(`{"id":"697807559","n":"500"}`)
	if !ok || !bytes.Equal(got, want) {
		t.Fatalf("DecryptRequest=%q,%v want %q", got, ok, want)
	}
}

func TestDecryptRejectsPlainText(t *testing.T) {
	if _, ok := DecryptResponse([]byte(`{"code":200}`)); ok {
		t.Fatal("明文 JSON 不应被判定为 EAPI 密文")
	}
	if _, ok := DecryptRequest([]byte("a=1&b=2")); ok {
		t.Fatal("不含 params 的请求不应被解密")
	}
}
