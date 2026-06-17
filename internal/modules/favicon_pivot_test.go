package modules

import "testing"

// Known mmh3.hash (32-bit, signed, seed 0) vectors, matching Python's mmh3
// library — favicon pivot must produce identical hashes for Shodan parity.
func TestMurmur3Hash32(t *testing.T) {
	cases := []struct {
		in   string
		want int32
	}{
		{"", 0},
		{"hello", 613153351},
		{"The quick brown fox jumps over the lazy dog", 776992547},
	}
	for _, c := range cases {
		if got := murmur3Hash32([]byte(c.in), 0); got != c.want {
			t.Errorf("murmur3Hash32(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}
