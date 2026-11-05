// Package policy holds gobl's decision logic as pure functions:
// time-based decay, the permaban threshold and forgiveness.
package policy

// Params are the policy settings, in seconds.
type Params struct {
	Timeout int64 // decay period (permaban_timeout)
	Retry   int64 // permaban threshold (permaban_retry)
	Forgive int64 // 0 = never forgive (permaban_forgive)
}

// Record is the per-IP state.
type Record struct {
	Counter     int64
	FirstSeen   int64
	LastSeen    int64
	DecayAnchor int64
	Perm        bool
	PermSince   int64 // 0 if not perm
}

// Decay lowers the counter of a non-perm record by one per full Timeout
// elapsed since DecayAnchor, and moves the anchor forward by those periods.
func Decay(r Record, now int64, p Params) Record {
	if r.Perm || p.Timeout <= 0 || now <= r.DecayAnchor {
		return r
	}
	n := (now - r.DecayAnchor) / p.Timeout
	if n == 0 {
		return r
	}
	r.DecayAnchor += n * p.Timeout
	r.Counter -= n
	if r.Counter < 0 {
		r.Counter = 0
	}
	return r
}

// Ban applies one ban to r (nil means a new IP) and returns the new state.
func Ban(r *Record, now int64, p Params) Record {
	var rec Record
	if r == nil {
		rec = Record{FirstSeen: now, DecayAnchor: now}
	} else {
		rec = Decay(*r, now, p)
	}
	rec.Counter++
	rec.LastSeen = now
	rec.DecayAnchor = now
	if !rec.Perm && rec.Counter >= p.Retry {
		rec.Perm = true
		rec.PermSince = now
	}
	return rec
}

// Outcome is what maintain should do with a record.
type Outcome int

const (
	Keep    Outcome = iota // record stays (possibly updated)
	Expire                 // non-perm record decayed to zero: delete, remove from temp set
	Forgive                // perm record forgiven: delete, remove from perm and temp sets
)

// Maintain decides the fate of a record at time now.
func Maintain(r Record, now int64, p Params) (Record, Outcome) {
	if r.Perm {
		if p.Forgive > 0 && now-r.LastSeen > p.Forgive {
			return r, Forgive
		}
		return r, Keep
	}
	r = Decay(r, now, p)
	if r.Counter <= 0 {
		return r, Expire
	}
	return r, Keep
}

// RemotePerm merges a permaban that another host last saw at ts into the
// local record cur (nil if there is none). pardonTS is the newest known
// pardon for the IP (0 if none). It returns the new record and whether
// anything changed. Rules, last writer wins:
//   - a pardon at or after ts cancels the remote permaban;
//   - a remote permaban older than the forgive period is ignored;
//   - otherwise the IP becomes (or stays) perm and last_seen is the newest
//     of both sides, which extends the forgive period consistently everywhere.
func RemotePerm(cur *Record, ts, pardonTS, now int64, p Params) (Record, bool) {
	if pardonTS >= ts {
		if cur != nil {
			return *cur, false
		}
		return Record{}, false
	}
	if p.Forgive > 0 && now-ts > p.Forgive {
		if cur != nil {
			return *cur, false
		}
		return Record{}, false
	}
	if cur == nil {
		return Record{Counter: p.Retry, FirstSeen: ts, LastSeen: ts, DecayAnchor: ts, Perm: true, PermSince: ts}, true
	}
	r := *cur
	changed := false
	if !r.Perm {
		r.Perm = true
		r.PermSince = ts
		changed = true
	}
	if ts > r.LastSeen {
		r.LastSeen = ts
		changed = true
	}
	return r, changed
}

// PardonApplies reports whether a pardon made at pardonTS removes the
// record: only if nothing happened to the IP after the pardon.
func PardonApplies(r Record, pardonTS int64) bool { return r.LastSeen <= pardonTS }
