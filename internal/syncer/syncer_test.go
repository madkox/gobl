package syncer

import (
	"context"
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/alicebob/miniredis/v2"

	"gobl/internal/config"
	"gobl/internal/policy"
	"gobl/internal/store"
)

const day = 86400

func host(t *testing.T, mr *miniredis.Miniredis) (*store.Store, *Redis) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "gobl.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	cfg := config.Default()
	cfg.RedisURL = "redis://" + mr.Addr() + "/0"
	cfg.RedisDB = 3
	r, err := Dial(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	return st, r
}

func TestTwoHostsConverge(t *testing.T) {
	mr := miniredis.RunT(t)
	ctx := context.Background()
	p := policy.Params{Timeout: day, Retry: 1, Forgive: 30 * day}
	now := int64(1000 * day)

	stA, rA := host(t, mr)
	stB, rB := host(t, mr)
	a := netip.MustParseAddr("1.1.1.1")
	b := netip.MustParseAddr("2001:db8::2")
	old := netip.MustParseAddr("3.3.3.3")
	stA.Ban(a, "sshd", now-day, p, false)
	stB.Ban(b, "nginx", now-2*day, p, false)
	stB.Ban(old, "nginx", now-40*day, p, false) // older than forgive, maintain not run yet

	// A syncs first (sees nothing new), then B (gets a), then A again (gets b).
	if _, err := Run(ctx, stA, rA, "a", now, p); err != nil {
		t.Fatal(err)
	}
	resB, err := Run(ctx, stB, rB, "b", now, p)
	if err != nil {
		t.Fatal(err)
	}
	if len(resB.Merge.NewPerm) != 1 || resB.Merge.NewPerm[0] != a {
		t.Fatalf("B merge = %+v", resB.Merge)
	}
	resA, err := Run(ctx, stA, rA, "a", now, p)
	if err != nil {
		t.Fatal(err)
	}
	if len(resA.Merge.NewPerm) != 1 || resA.Merge.NewPerm[0] != b {
		t.Fatalf("A merge = %+v", resA.Merge)
	}
	if h, _ := stA.Get(old); h != nil {
		t.Fatal("entry older than forgive period must not propagate")
	}
	if members, _ := mr.DB(3).ZMembers("f2b:perm"); len(members) != 2 {
		t.Fatalf("redis perm after trim = %v", members)
	}

	// B pardons a; after both sync, a is gone everywhere and stays gone.
	if _, err := stB.Pardon(a, now+10, false); err != nil {
		t.Fatal(err)
	}
	Run(ctx, stB, rB, "b", now+20, p)
	resA, _ = Run(ctx, stA, rA, "a", now+30, p)
	if len(resA.Merge.Pardoned) != 1 || resA.Merge.Pardoned[0] != a {
		t.Fatalf("A pardon merge = %+v", resA.Merge)
	}
	if h, _ := stA.Get(a); h != nil {
		t.Fatalf("a still present on A: %+v", h)
	}
	resB, _ = Run(ctx, stB, rB, "b", now+40, p)
	if h, _ := stB.Get(a); h != nil || resB.Merge.Updated != 0 {
		t.Fatalf("pardoned IP resurrected on B: %+v %+v", h, resB.Merge)
	}

	// Nodes hash records both hosts.
	if nodes, _ := mr.DB(3).HKeys("f2b:nodes"); len(nodes) != 2 {
		t.Fatalf("nodes = %v", nodes)
	}
	// Separate redis_db setting overrides the URL's /0.
	if mr.DB(3).Exists("f2b:perm") == false {
		t.Fatal("data not in db 3")
	}
}

func TestInvalidMembersSkipped(t *testing.T) {
	mr := miniredis.RunT(t)
	st, r := host(t, mr)
	mr.DB(3).ZAdd("f2b:perm", 1e9, "not-an-ip")
	mr.DB(3).ZAdd("f2b:perm", 1e9, "4.4.4.4")
	res, err := Run(context.Background(), st, r, "x", 1e9, policy.Params{Timeout: day, Retry: 1})
	if err != nil {
		t.Fatal(err)
	}
	if res.Invalid != 1 || len(res.Merge.NewPerm) != 1 {
		t.Fatalf("res = %+v", res)
	}
}

func TestOptions(t *testing.T) {
	cfg := config.Default()
	cfg.RedisURL = "rediss://u:p@redis.example:6380/2"
	opts, err := Options(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if opts.DB != 2 || opts.Username != "u" || opts.Password != "p" || opts.TLSConfig == nil {
		t.Fatalf("opts = %+v", opts)
	}
	cfg.RedisDB, cfg.RedisUsername, cfg.RedisPassword = 5, "gobl", "s#cret"
	opts, _ = Options(cfg)
	if opts.DB != 5 || opts.Username != "gobl" || opts.Password != "s#cret" {
		t.Fatalf("overrides not applied: %+v", opts)
	}
	cfg.RedisURL = "redis://h:6379"
	cfg.RedisTLSCA = "/nonexistent"
	if _, err := Options(cfg); err == nil {
		t.Fatal("redis_tls_ca without rediss:// must fail")
	}
}
