package policy

import "testing"

const day = 86400

func TestRetryOneMeansFirstBanIsPerm(t *testing.T) {
	r := Ban(nil, 1000, Params{Timeout: day, Retry: 1})
	if !r.Perm || r.Counter != 1 || r.PermSince != 1000 {
		t.Fatalf("got %+v", r)
	}
}

func TestThreshold(t *testing.T) {
	p := Params{Timeout: day, Retry: 3}
	r := Ban(nil, 0, p)
	r = Ban(&r, 10, p)
	if r.Perm || r.Counter != 2 {
		t.Fatalf("after 2 bans: %+v", r)
	}
	r = Ban(&r, 20, p)
	if !r.Perm || r.Counter != 3 || r.PermSince != 20 || r.FirstSeen != 0 {
		t.Fatalf("after 3 bans: %+v", r)
	}
}

func TestDecayIsTimeBased(t *testing.T) {
	p := Params{Timeout: day, Retry: 10}
	r := Record{Counter: 5, DecayAnchor: 0}
	if got := Decay(r, day-1, p); got.Counter != 5 {
		t.Fatalf("decayed too early: %+v", got)
	}
	got := Decay(r, 2*day+100, p)
	if got.Counter != 3 || got.DecayAnchor != 2*day {
		t.Fatalf("got %+v", got)
	}
	// Running decay often must give the same result as running it once.
	step := r
	for now := int64(0); now <= 2*day+100; now += 3600 {
		step = Decay(step, now, p)
	}
	if step.Counter != got.Counter || step.DecayAnchor != got.DecayAnchor {
		t.Fatalf("frequency-dependent: %+v vs %+v", step, got)
	}
	if got := Decay(r, 100*day, p); got.Counter != 0 {
		t.Fatalf("counter below zero or not decayed: %+v", got)
	}
}

func TestBanDecaysFirst(t *testing.T) {
	p := Params{Timeout: day, Retry: 3}
	r := Ban(nil, 0, p)
	r = Ban(&r, 10, p) // counter 2
	r = Ban(&r, 10+2*day, p)
	if r.Perm || r.Counter != 1 {
		t.Fatalf("expected decay to 0 then +1: %+v", r)
	}
}

func TestPermDoesNotDecay(t *testing.T) {
	r := Record{Counter: 1, Perm: true}
	if got := Decay(r, 10*day, Params{Timeout: day}); got.Counter != 1 {
		t.Fatalf("got %+v", got)
	}
}

func TestMaintain(t *testing.T) {
	p := Params{Timeout: day, Retry: 3, Forgive: 30 * day}

	if _, o := Maintain(Record{Counter: 1, DecayAnchor: 0}, day, p); o != Expire {
		t.Fatalf("expected Expire, got %v", o)
	}
	if r, o := Maintain(Record{Counter: 2, DecayAnchor: 0}, day, p); o != Keep || r.Counter != 1 {
		t.Fatalf("expected Keep/1, got %v %+v", o, r)
	}
	perm := Record{Counter: 3, Perm: true, LastSeen: 0}
	if _, o := Maintain(perm, 30*day, p); o != Keep {
		t.Fatalf("forgiven too early: %v", o)
	}
	if _, o := Maintain(perm, 30*day+1, p); o != Forgive {
		t.Fatalf("expected Forgive, got %v", o)
	}
	p.Forgive = 0
	if _, o := Maintain(perm, 1000*day, p); o != Keep {
		t.Fatalf("forgive disabled but got %v", o)
	}
}

func TestRemotePerm(t *testing.T) {
	p := Params{Timeout: day, Retry: 3, Forgive: 30 * day}
	now := int64(100 * day)

	r, ch := RemotePerm(nil, now-day, 0, now, p)
	if !ch || !r.Perm || r.LastSeen != now-day || r.Counter != 3 {
		t.Fatalf("new: %+v %v", r, ch)
	}
	if _, ch := RemotePerm(nil, now-31*day, 0, now, p); ch {
		t.Fatal("expired remote perm must be ignored")
	}
	if _, ch := RemotePerm(nil, now-day, now-day, now, p); ch {
		t.Fatal("pardon at same time must win")
	}
	if r, ch := RemotePerm(nil, now-day, now-2*day, now, p); !ch || !r.Perm {
		t.Fatal("older pardon must not cancel newer perm")
	}

	local := Record{Counter: 1, LastSeen: now - 5*day, DecayAnchor: now - 5*day}
	r, ch = RemotePerm(&local, now-day, 0, now, p)
	if !ch || !r.Perm || r.Counter != 1 || r.LastSeen != now-day {
		t.Fatalf("upgrade: %+v", r)
	}
	perm := Record{Perm: true, LastSeen: now}
	if r, ch := RemotePerm(&perm, now-day, 0, now, p); ch || r.LastSeen != now {
		t.Fatalf("older remote must not change newer local: %+v %v", r, ch)
	}
	// Merge is idempotent.
	once, _ := RemotePerm(&local, now-day, 0, now, p)
	if _, ch := RemotePerm(&once, now-day, 0, now, p); ch {
		t.Fatal("second merge of same entry changed something")
	}
}

func TestPardonApplies(t *testing.T) {
	if !PardonApplies(Record{LastSeen: 10}, 10) || PardonApplies(Record{LastSeen: 11}, 10) {
		t.Fatal("pardon must win only if nothing happened after it")
	}
}
