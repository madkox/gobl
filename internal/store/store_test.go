package store

import (
	"fmt"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"

	"gobl/internal/policy"
)

const day = 86400

func open(t *testing.T, path string) *Store {
	t.Helper()
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestBanAndThreshold(t *testing.T) {
	s := open(t, filepath.Join(t.TempDir(), "gobl.db"))
	p := policy.Params{Timeout: day, Retry: 2, Forgive: 30 * day}
	ip := netip.MustParseAddr("2001:db8::1")

	h, err := s.Ban(ip, "sshd", 100, p, true)
	if err != nil || h.Perm || h.Counter != 1 || h.Family != 6 {
		t.Fatalf("first ban: %+v %v", h, err)
	}
	h, err = s.Ban(ip, "sshd", 200, p, true)
	if err != nil || !h.Perm || h.Counter != 2 || h.FirstSeen != 100 {
		t.Fatalf("second ban: %+v %v", h, err)
	}
	perm, _ := s.PermIPs()
	if len(perm) != 1 || perm[0] != ip {
		t.Fatalf("PermIPs = %v", perm)
	}
}

func TestMaintain(t *testing.T) {
	s := open(t, filepath.Join(t.TempDir(), "gobl.db"))
	p := policy.Params{Timeout: day, Retry: 3, Forgive: 10 * day}
	a := netip.MustParseAddr("1.1.1.1") // one ban -> expires after a day
	b := netip.MustParseAddr("2.2.2.2") // two bans -> decays to 1
	c := netip.MustParseAddr("3.3.3.3") // perm -> forgiven after 10 days
	s.Ban(a, "", 0, p, true)
	s.Ban(b, "", 0, p, true)
	s.Ban(b, "", 0, p, true)
	for range 3 {
		s.Ban(c, "", 0, p, true)
	}

	res, err := s.Maintain(day, p, day/2)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Expired) != 1 || res.Expired[0].IP != a || len(res.Forgiven) != 0 || res.Kept != 2 {
		t.Fatalf("day 1: %+v", res)
	}
	if h, _ := s.Get(b); h == nil || h.Counter != 1 {
		t.Fatalf("b = %+v", h)
	}
	res, _ = s.Maintain(11*day, p, day)
	if len(res.Forgiven) != 1 || res.Forgiven[0].IP != c || len(res.Expired) != 1 {
		t.Fatalf("day 11: %+v", res)
	}
	if all, _ := s.List(false); len(all) != 0 {
		t.Fatalf("left: %+v", all)
	}
}

func TestPardonAndImport(t *testing.T) {
	s := open(t, filepath.Join(t.TempDir(), "gobl.db"))
	ip := netip.MustParseAddr("1.2.3.4")
	ins, skip, err := s.Import([]Host{{IP: ip, Family: 4, Record: policy.Record{Counter: 3, Perm: true}, Source: "local"}})
	if err != nil || ins != 1 || skip != 0 {
		t.Fatal(ins, skip, err)
	}
	ins, skip, _ = s.Import([]Host{{IP: ip, Family: 4, Source: "local"}})
	if ins != 0 || skip != 1 {
		t.Fatal("existing row should win", ins, skip)
	}
	existed, err := s.Pardon(ip, 10, true)
	if err != nil || !existed {
		t.Fatal(existed, err)
	}
	if h, _ := s.Get(ip); h != nil {
		t.Fatalf("still present: %+v", h)
	}
}

// Many separate Store instances (like separate gobl processes) banning the
// same IPs at once must not lose a single update.
func TestConcurrentBansLoseNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gobl.db")
	open(t, path) // create schema
	p := policy.Params{Timeout: day, Retry: 1 << 30}
	const workers, perWorker, ips = 16, 50, 5

	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for w := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s, err := Open(path)
			if err != nil {
				errs <- err
				return
			}
			defer s.Close()
			for i := range perWorker {
				ip := netip.MustParseAddr(fmt.Sprintf("10.0.0.%d", (w+i)%ips+1))
				if _, err := s.Ban(ip, "", 1000, p, true); err != nil {
					errs <- err
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}

	s := open(t, path)
	all, _ := s.List(false)
	var total int64
	for _, h := range all {
		total += h.Counter
	}
	if total != workers*perWorker {
		t.Fatalf("lost updates: total counter %d, want %d", total, workers*perWorker)
	}
}

func TestMerge(t *testing.T) {
	s := open(t, filepath.Join(t.TempDir(), "gobl.db"))
	p := policy.Params{Timeout: day, Retry: 3, Forgive: 30 * day}
	now := int64(100 * day)
	a := netip.MustParseAddr("1.1.1.1")     // new remote perm
	b := netip.MustParseAddr("2.2.2.2")     // local temp, upgraded
	c := netip.MustParseAddr("3.3.3.3")     // local perm, pardoned remotely
	d := netip.MustParseAddr("2001:db8::4") // local perm, re-banned after remote pardon
	s.Ban(b, "", now-2*day, p, false)
	for range 3 {
		s.Ban(c, "", now-5*day, p, false)
		s.Ban(d, "", now-day, p, false)
	}

	perms := []Entry{{a, now - day}, {b, now - day}}
	pardons := []Entry{{c, now - 4*day}, {d, now - 2*day}}
	res, err := s.Merge(perms, pardons, now, p)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.NewPerm) != 2 || len(res.Pardoned) != 1 || res.Pardoned[0] != c {
		t.Fatalf("res = %+v", res)
	}
	if h, _ := s.Get(a); h == nil || !h.Perm || h.Source != "sync" {
		t.Fatalf("a = %+v", h)
	}
	if h, _ := s.Get(b); h == nil || !h.Perm || h.Source != "local" || h.Counter != 1 {
		t.Fatalf("b = %+v", h)
	}
	if h, _ := s.Get(d); h == nil || !h.Perm {
		t.Fatalf("d must survive an older pardon: %+v", h)
	}
	// A pardoned IP must not come back from a stale remote perm entry.
	res, _ = s.Merge([]Entry{{c, now - 5*day}}, nil, now, p)
	if res.Updated != 0 {
		t.Fatalf("stale perm resurrected pardoned IP: %+v", res)
	}
	// Idempotent.
	res, _ = s.Merge(perms, pardons, now, p)
	if res.Updated != 0 {
		t.Fatalf("second merge changed rows: %+v", res)
	}
	pd, _ := s.Pardons()
	if len(pd) != 2 {
		t.Fatalf("pardons = %v", pd)
	}
}
