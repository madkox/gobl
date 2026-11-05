package nft

import (
	"net/netip"
	"testing"
)

func TestParseSetJSON(t *testing.T) {
	data := []byte(`{"nftables": [{"metainfo": {"version": "1.1.3"}},
		{"set": {"family": "inet", "name": "f2b_temp", "table": "filter", "type": "ipv4_addr",
		 "elem": ["1.2.3.4", {"elem": {"val": "5.6.7.8", "timeout": 60}}]}}]}`)
	got, err := parseSetJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != netip.MustParseAddr("1.2.3.4") || got[1] != netip.MustParseAddr("5.6.7.8") {
		t.Fatalf("got %v", got)
	}
}

func TestMissingPresent(t *testing.T) {
	a, b, c := netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("2.2.2.2"), netip.MustParseAddr("::1")
	if m := Missing([]netip.Addr{a, b, c}, []netip.Addr{b}); len(m) != 2 || m[0] != a || m[1] != c {
		t.Fatalf("Missing = %v", m)
	}
	if p := Present([]netip.Addr{a, b, c}, []netip.Addr{b}); len(p) != 1 || p[0] != b {
		t.Fatalf("Present = %v", p)
	}
}
