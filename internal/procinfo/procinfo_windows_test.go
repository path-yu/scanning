//go:build windows

package procinfo

import "testing"

func TestDecodePort(t *testing.T) {
	cases := []struct {
		raw  uint32
		want int
	}{
		{0x5000, 80},
		{0xC322, 8899},
		{0x0000, 0},
	}
	for _, tc := range cases {
		if got := decodePort(tc.raw); got != tc.want {
			t.Fatalf("decodePort(%#x) = %d，期望 %d", tc.raw, got, tc.want)
		}
	}
}

func TestTCPStateName(t *testing.T) {
	cases := map[uint32]string{2: "LISTEN", 3: "SYN_SENT", 5: "ESTABLISHED", 11: "TIME_WAIT"}
	for state, want := range cases {
		if got := tcpStateName(state); got != want {
			t.Fatalf("tcpStateName(%d) = %q，期望 %q", state, got, want)
		}
	}
}

func TestIPv4DWORD(t *testing.T) {
	raw := ipv4ToDWORD([]byte{127, 0, 0, 1})
	if raw != 0x0100007F {
		t.Fatalf("ipv4ToDWORD = %#x", raw)
	}
	if got := ipv4FromDWORD(raw); got != "127.0.0.1" {
		t.Fatalf("ipv4FromDWORD = %q", got)
	}
}
