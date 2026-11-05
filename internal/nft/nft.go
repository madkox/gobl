// Package nft manipulates the nftables sets gobl bans into. The netlink
// backend talks to the kernel directly; the exec backend runs the `nft`
// binary (without a shell) as a fallback.
package nft

import (
	"fmt"
	"net/netip"
)

// Backend is the set operations gobl needs. Add of an existing element and
// Delete of a missing element both succeed.
type Backend interface {
	// EnsureSet creates the set (ipv4_addr or ipv6_addr) if it is missing.
	// The table must already exist; gobl never creates tables or rules.
	EnsureSet(name string, v6 bool) error
	Add(set string, ips []netip.Addr) error
	Delete(set string, ips []netip.Addr) error
	Flush(set string) error
	List(set string) ([]netip.Addr, error)
	Close() error
}

// New returns a backend of the given kind ("netlink" or "exec") for the
// table <family> <name>.
func New(kind, family, table string) (Backend, error) {
	switch kind {
	case "netlink":
		return newNetlink(family, table)
	case "exec":
		return newExec(family, table), nil
	default:
		return nil, fmt.Errorf("unknown nft backend %q", kind)
	}
}

// Missing returns the elements of want that are not in have.
func Missing(want, have []netip.Addr) []netip.Addr {
	in := make(map[netip.Addr]struct{}, len(have))
	for _, a := range have {
		in[a] = struct{}{}
	}
	var out []netip.Addr
	for _, a := range want {
		if _, ok := in[a]; !ok {
			out = append(out, a)
		}
	}
	return out
}

// Present returns the elements of want that are in have.
func Present(want, have []netip.Addr) []netip.Addr {
	in := make(map[netip.Addr]struct{}, len(have))
	for _, a := range have {
		in[a] = struct{}{}
	}
	var out []netip.Addr
	for _, a := range want {
		if _, ok := in[a]; ok {
			out = append(out, a)
		}
	}
	return out
}
