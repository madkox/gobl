package nft

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/google/nftables"
	"golang.org/x/sys/unix"
)

// batchSize caps the number of elements per netlink batch.
const batchSize = 1000

type netlinkBackend struct {
	conn   *nftables.Conn
	family nftables.TableFamily
	name   string
	table  *nftables.Table
}

func newNetlink(family, table string) (*netlinkBackend, error) {
	var fam nftables.TableFamily
	switch family {
	case "inet":
		fam = nftables.TableFamilyINet
	case "ip":
		fam = nftables.TableFamilyIPv4
	case "ip6":
		fam = nftables.TableFamilyIPv6
	default:
		return nil, fmt.Errorf("unsupported table family %q", family)
	}
	conn, err := nftables.New()
	if err != nil {
		return nil, fmt.Errorf("netlink: %w", err)
	}
	return &netlinkBackend{conn: conn, family: fam, name: table}, nil
}

func (b *netlinkBackend) Close() error { return nil }

func (b *netlinkBackend) getTable() (*nftables.Table, error) {
	if b.table != nil {
		return b.table, nil
	}
	t, err := b.conn.ListTableOfFamily(b.name, b.family)
	if err != nil {
		return nil, fmt.Errorf("table %s: %w", b.name, err)
	}
	b.table = t
	return t, nil
}

func (b *netlinkBackend) getSet(name string) (*nftables.Set, error) {
	t, err := b.getTable()
	if err != nil {
		return nil, err
	}
	s, err := b.conn.GetSetByName(t, name)
	if err != nil {
		return nil, fmt.Errorf("set %s: %w", name, err)
	}
	if s.Interval || s.Concatenation {
		return nil, fmt.Errorf("set %s: interval and concatenated sets are not supported", name)
	}
	return s, nil
}

func (b *netlinkBackend) EnsureSet(name string, v6 bool) error {
	t, err := b.getTable()
	if err != nil {
		return err
	}
	want := nftables.TypeIPAddr
	if v6 {
		want = nftables.TypeIP6Addr
	}
	if s, err := b.conn.GetSetByName(t, name); err == nil {
		if s.KeyType.Name != want.Name {
			return fmt.Errorf("set %s has type %s, want %s", name, s.KeyType.Name, want.Name)
		}
		return nil
	}
	if err := b.conn.AddSet(&nftables.Set{Table: t, Name: name, KeyType: want}, nil); err != nil {
		return fmt.Errorf("add set %s: %w", name, err)
	}
	if err := b.conn.Flush(); err != nil {
		return fmt.Errorf("add set %s: %w", name, err)
	}
	return nil
}

func elements(s *nftables.Set, ips []netip.Addr) ([]nftables.SetElement, error) {
	out := make([]nftables.SetElement, 0, len(ips))
	for _, ip := range ips {
		key := ip.AsSlice()
		if uint32(len(key)) != s.KeyType.Bytes {
			return nil, fmt.Errorf("address %s does not fit set %s (%s)", ip, s.Name, s.KeyType.Name)
		}
		out = append(out, nftables.SetElement{Key: key})
	}
	return out, nil
}

func (b *netlinkBackend) Add(set string, ips []netip.Addr) error {
	if len(ips) == 0 {
		return nil
	}
	s, err := b.getSet(set)
	if err != nil {
		return err
	}
	for start := 0; start < len(ips); start += batchSize {
		chunk := ips[start:min(start+batchSize, len(ips))]
		els, err := elements(s, chunk)
		if err != nil {
			return err
		}
		if err := b.conn.SetAddElements(s, els); err != nil {
			return err
		}
		if err := b.conn.Flush(); err != nil {
			return fmt.Errorf("add to %s: %w", set, err)
		}
	}
	return nil
}

func (b *netlinkBackend) Delete(set string, ips []netip.Addr) error {
	if len(ips) == 0 {
		return nil
	}
	s, err := b.getSet(set)
	if err != nil {
		return err
	}
	// The kernel rejects the whole batch if one element is missing, so for
	// more than one address delete only those that are present.
	if len(ips) > 1 {
		have, err := b.list(s)
		if err != nil {
			return err
		}
		ips = Present(ips, have)
	}
	for start := 0; start < len(ips); start += batchSize {
		els, err := elements(s, ips[start:min(start+batchSize, len(ips))])
		if err != nil {
			return err
		}
		if err := b.conn.SetDeleteElements(s, els); err != nil {
			return err
		}
		if err := b.conn.Flush(); err != nil {
			if errors.Is(err, unix.ENOENT) {
				continue // already gone
			}
			return fmt.Errorf("delete from %s: %w", set, err)
		}
	}
	return nil
}

func (b *netlinkBackend) Flush(set string) error {
	s, err := b.getSet(set)
	if err != nil {
		return err
	}
	b.conn.FlushSet(s)
	if err := b.conn.Flush(); err != nil {
		return fmt.Errorf("flush %s: %w", set, err)
	}
	return nil
}

func (b *netlinkBackend) List(set string) ([]netip.Addr, error) {
	s, err := b.getSet(set)
	if err != nil {
		return nil, err
	}
	return b.list(s)
}

func (b *netlinkBackend) list(s *nftables.Set) ([]netip.Addr, error) {
	els, err := b.conn.GetSetElements(s)
	if err != nil {
		return nil, fmt.Errorf("list %s: %w", s.Name, err)
	}
	out := make([]netip.Addr, 0, len(els))
	for _, e := range els {
		if a, ok := netip.AddrFromSlice(e.Key); ok {
			out = append(out, a.Unmap())
		}
	}
	return out, nil
}
