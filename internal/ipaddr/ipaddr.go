// Package ipaddr parses and normalizes addresses passed by fail2ban.
package ipaddr

import (
	"fmt"
	"net/netip"
)

// Parse returns a normalized address: IPv4-mapped IPv6 becomes IPv4.
// Zones, prefixes and unspecified addresses are rejected.
func Parse(s string) (netip.Addr, error) {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("invalid IP address %q", s)
	}
	if a.Zone() != "" {
		return netip.Addr{}, fmt.Errorf("IP address with zone not allowed: %q", s)
	}
	a = a.Unmap()
	if a.IsUnspecified() {
		return netip.Addr{}, fmt.Errorf("unspecified IP address not allowed: %q", s)
	}
	return a, nil
}

// Family returns 4 or 6.
func Family(a netip.Addr) int {
	if a.Is4() {
		return 4
	}
	return 6
}
