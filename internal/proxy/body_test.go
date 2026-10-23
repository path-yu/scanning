package proxy

import "testing"

func TestDecodePreviewRejectsBinaryEvenWithTextMime(t *testing.T) {
	// 网易云 EAPI 响应开头为 's'，随后是加密二进制，但服务端 Content-Type 为 text/plain。
	data := make([]byte, 256)
	data[0] = 's'
	for i := 1; i < len(data); i++ {
		data[i] = byte(0x80 + i%0x40)
	}
	data[32] = 0
	text, preview := decodePreview(data, "", "text/plain;charset=UTF-8")
	if text {
		t.Fatalf("二进制正文不应被判定为文本，preview=%q", preview)
	}
	if preview != "" {
		t.Fatalf("二进制正文不应生成预览，得到 %q", preview)
	}
}

func TestDecodePreviewAcceptsJSON(t *testing.T) {
	text, preview := decodePreview([]byte(`{"code":200,"message":"ok"}`), "", "text/plain;charset=UTF-8")
	if !text {
		t.Fatal("JSON 正文应判定为文本")
	}
	if preview == "" {
		t.Fatal("JSON 正文应生成预览")
	}
}
