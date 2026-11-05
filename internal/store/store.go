// Package store keeps gobl's per-IP state in SQLite (WAL mode). Every
// write runs in a BEGIN IMMEDIATE transaction, so concurrent gobl processes
// are serialized and no update is lost.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"

	"gobl/internal/ipaddr"
	"gobl/internal/policy"

	_ "modernc.org/sqlite"
)

// Host is one row of the hosts table.
type Host struct {
	IP     netip.Addr
	Family int
	policy.Record
	Source    string // "local" or "remote:<node>"
	UpdatedAt int64
}

// Store wraps the SQLite database.
type Store struct {
	db *sql.DB
}

var migrations = []string{
	`CREATE TABLE hosts (
		ip           TEXT PRIMARY KEY,
		family       INTEGER NOT NULL,
		counter      INTEGER NOT NULL,
		first_seen   INTEGER NOT NULL,
		last_seen    INTEGER NOT NULL,
		decay_anchor INTEGER NOT NULL,
		perm         INTEGER NOT NULL DEFAULT 0,
		perm_since   INTEGER NOT NULL DEFAULT 0,
		source       TEXT    NOT NULL DEFAULT 'local',
		updated_at   INTEGER NOT NULL
	);
	CREATE INDEX hosts_perm ON hosts(perm);
	CREATE INDEX hosts_updated ON hosts(updated_at);
	CREATE TABLE pardons (ip TEXT PRIMARY KEY, ts INTEGER NOT NULL);
	CREATE TABLE events (
		ts     INTEGER NOT NULL,
		ip     TEXT    NOT NULL,
		jail   TEXT    NOT NULL DEFAULT '',
		action TEXT    NOT NULL
	);
	CREATE INDEX events_ts ON events(ts);
	CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);`,
}

// Open opens (creating if needed) the database at path and applies migrations.
func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("create db dir: %w", err)
	}
	q := url.Values{}
	q.Add("_pragma", "busy_timeout(10000)")
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "synchronous(NORMAL)")
	q.Set("_txlock", "immediate")
	db, err := sql.Open("sqlite", "file:"+path+"?"+q.Encode())
	if err != nil {
		return nil, err
	}
	// gobl is a short-lived CLI; one connection per process is enough and
	// avoids lock contention inside the process.
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate %s: %w", path, err)
	}
	return s, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	var version int
	if err := s.db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return err
	}
	if version >= len(migrations) {
		return nil
	}
	return s.tx(func(tx *sql.Tx) error {
		// Re-check inside the write lock: another process may have migrated.
		if err := tx.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
			return err
		}
		for i := version; i < len(migrations); i++ {
			if _, err := tx.Exec(migrations[i]); err != nil {
				return fmt.Errorf("migration %d: %w", i+1, err)
			}
		}
		_, err := tx.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, len(migrations)))
		return err
	})
}

func (s *Store) tx(fn func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

const hostCols = `ip, family, counter, first_seen, last_seen, decay_anchor, perm, perm_since, source, updated_at`

type scanner interface{ Scan(...any) error }

func scanHost(sc scanner) (Host, error) {
	var h Host
	var ip string
	err := sc.Scan(&ip, &h.Family, &h.Counter, &h.FirstSeen, &h.LastSeen, &h.DecayAnchor,
		&h.Perm, &h.PermSince, &h.Source, &h.UpdatedAt)
	if err != nil {
		return h, err
	}
	h.IP, err = netip.ParseAddr(ip)
	return h, err
}

func getHost(q interface {
	QueryRow(string, ...any) *sql.Row
}, ip netip.Addr) (*Host, error) {
	h, err := scanHost(q.QueryRow(`SELECT `+hostCols+` FROM hosts WHERE ip = ?`, ip.String()))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &h, nil
}

func putHost(tx *sql.Tx, h Host) error {
	_, err := tx.Exec(`INSERT INTO hosts (`+hostCols+`) VALUES (?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(ip) DO UPDATE SET
			counter=excluded.counter, first_seen=excluded.first_seen, last_seen=excluded.last_seen,
			decay_anchor=excluded.decay_anchor, perm=excluded.perm, perm_since=excluded.perm_since,
			source=excluded.source, updated_at=excluded.updated_at`,
		h.IP.String(), h.Family, h.Counter, h.FirstSeen, h.LastSeen, h.DecayAnchor,
		h.Perm, h.PermSince, h.Source, h.UpdatedAt)
	return err
}

func logEvent(tx *sql.Tx, now int64, ip netip.Addr, jail, action string) error {
	_, err := tx.Exec(`INSERT INTO events (ts, ip, jail, action) VALUES (?,?,?,?)`, now, ip.String(), jail, action)
	return err
}

// Ban records one ban of ip and returns the resulting state.
func (s *Store) Ban(ip netip.Addr, jail string, now int64, p policy.Params, logEvents bool) (Host, error) {
	var out Host
	err := s.tx(func(tx *sql.Tx) error {
		cur, err := getHost(tx, ip)
		if err != nil {
			return err
		}
		var rec *policy.Record
		if cur != nil {
			rec = &cur.Record
		}
		// A local ban makes the record local, even if it arrived via sync.
		out = Host{IP: ip, Family: ipaddr.Family(ip), Record: policy.Ban(rec, now, p), Source: "local", UpdatedAt: now}
		if err := putHost(tx, out); err != nil {
			return err
		}
		if logEvents {
			action := "ban"
			if out.Perm {
				action = "permaban"
			}
			return logEvent(tx, now, ip, jail, action)
		}
		return nil
	})
	return out, err
}

// LogEvent records an event outside of a ban (e.g. unban).
func (s *Store) LogEvent(now int64, ip netip.Addr, jail, action string) error {
	return s.tx(func(tx *sql.Tx) error { return logEvent(tx, now, ip, jail, action) })
}

// MaintainResult lists records removed by Maintain.
type MaintainResult struct {
	Expired  []Host // non-perm, decayed to zero
	Forgiven []Host // perm, forgiven
	Kept     int
}

// Maintain applies decay and forgiveness to every record and prunes old
// events. Removed records are returned so the caller can update nft.
func (s *Store) Maintain(now int64, p policy.Params, eventsRetention int64) (MaintainResult, error) {
	var res MaintainResult
	err := s.tx(func(tx *sql.Tx) error {
		res = MaintainResult{}
		rows, err := tx.Query(`SELECT ` + hostCols + ` FROM hosts`)
		if err != nil {
			return err
		}
		var hosts []Host
		for rows.Next() {
			h, err := scanHost(rows)
			if err != nil {
				rows.Close()
				return err
			}
			hosts = append(hosts, h)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}

		for _, h := range hosts {
			rec, outcome := policy.Maintain(h.Record, now, p)
			switch outcome {
			case policy.Keep:
				res.Kept++
				if rec != h.Record {
					h.Record = rec
					h.UpdatedAt = now
					if err := putHost(tx, h); err != nil {
						return err
					}
				}
				continue
			case policy.Expire:
				res.Expired = append(res.Expired, h)
			case policy.Forgive:
				res.Forgiven = append(res.Forgiven, h)
			}
			if _, err := tx.Exec(`DELETE FROM hosts WHERE ip = ?`, h.IP.String()); err != nil {
				return err
			}
		}

		if eventsRetention > 0 {
			if _, err := tx.Exec(`DELETE FROM events WHERE ts < ?`, now-eventsRetention); err != nil {
				return err
			}
		}
		// Pardon tombstones are only needed while a permaban could still
		// arrive from another host: keep them for the forgive period.
		if p.Forgive > 0 {
			if _, err := tx.Exec(`DELETE FROM pardons WHERE ts < ?`, now-p.Forgive); err != nil {
				return err
			}
		}
		return nil
	})
	return res, err
}

// PermIPs returns all permabanned addresses.
func (s *Store) PermIPs() ([]netip.Addr, error) {
	rows, err := s.db.Query(`SELECT ip FROM hosts WHERE perm = 1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []netip.Addr
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, err
		}
		a, err := netip.ParseAddr(ip)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// Get returns the record for ip, or nil if there is none.
func (s *Store) Get(ip netip.Addr) (*Host, error) { return getHost(s.db, ip) }

// List returns all records (only perm ones if permOnly), ordered by IP.
func (s *Store) List(permOnly bool) ([]Host, error) {
	q := `SELECT ` + hostCols + ` FROM hosts`
	if permOnly {
		q += ` WHERE perm = 1`
	}
	rows, err := s.db.Query(q + ` ORDER BY family, ip`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Host
	for rows.Next() {
		h, err := scanHost(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// Pardon deletes ip's record and leaves a tombstone for sync. It returns
// whether a record existed.
func (s *Store) Pardon(ip netip.Addr, now int64, logEvents bool) (bool, error) {
	var existed bool
	err := s.tx(func(tx *sql.Tx) error {
		r, err := tx.Exec(`DELETE FROM hosts WHERE ip = ?`, ip.String())
		if err != nil {
			return err
		}
		n, _ := r.RowsAffected()
		existed = n > 0
		if _, err := tx.Exec(`INSERT INTO pardons (ip, ts) VALUES (?, ?)
			ON CONFLICT(ip) DO UPDATE SET ts = excluded.ts`, ip.String(), now); err != nil {
			return err
		}
		if logEvents {
			return logEvent(tx, now, ip, "", "pardon")
		}
		return nil
	})
	return existed, err
}

// Import inserts hosts that are not already present. Existing rows win.
func (s *Store) Import(hosts []Host) (inserted, skipped int, err error) {
	err = s.tx(func(tx *sql.Tx) error {
		inserted, skipped = 0, 0
		for _, h := range hosts {
			r, err := tx.Exec(`INSERT INTO hosts (`+hostCols+`) VALUES (?,?,?,?,?,?,?,?,?,?)
				ON CONFLICT(ip) DO NOTHING`,
				h.IP.String(), h.Family, h.Counter, h.FirstSeen, h.LastSeen, h.DecayAnchor,
				h.Perm, h.PermSince, h.Source, h.UpdatedAt)
			if err != nil {
				return err
			}
			if n, _ := r.RowsAffected(); n > 0 {
				inserted++
			} else {
				skipped++
			}
		}
		return nil
	})
	return inserted, skipped, err
}

// Entry is an (IP, timestamp) pair exchanged during sync.
type Entry struct {
	IP netip.Addr
	TS int64
}

// PermEntries returns every permaban as (IP, last_seen).
func (s *Store) PermEntries() ([]Entry, error) {
	return s.entries(`SELECT ip, last_seen FROM hosts WHERE perm = 1`)
}

// Pardons returns every pardon tombstone as (IP, pardon time).
func (s *Store) Pardons() ([]Entry, error) {
	return s.entries(`SELECT ip, ts FROM pardons`)
}

func (s *Store) entries(q string) ([]Entry, error) {
	rows, err := s.db.Query(q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Entry
	for rows.Next() {
		var ip string
		var e Entry
		if err := rows.Scan(&ip, &e.TS); err != nil {
			return nil, err
		}
		if e.IP, err = netip.ParseAddr(ip); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// MergeResult tells the caller which nft changes the merge requires.
type MergeResult struct {
	NewPerm  []netip.Addr // became perm through sync: add to perm set
	Pardoned []netip.Addr // removed by a remote pardon: remove from all sets
	Updated  int          // rows changed in any way
}

// Merge applies remote permabans and pardons in one transaction, so it
// cannot race with concurrent bans. It is idempotent.
func (s *Store) Merge(perms, pardons []Entry, now int64, p policy.Params) (MergeResult, error) {
	var res MergeResult
	err := s.tx(func(tx *sql.Tx) error {
		res = MergeResult{}

		// Pardons first: record the newest tombstone per IP.
		pardonTS := map[netip.Addr]int64{}
		local, err := tx.Query(`SELECT ip, ts FROM pardons`)
		if err != nil {
			return err
		}
		for local.Next() {
			var ip string
			var ts int64
			if err := local.Scan(&ip, &ts); err != nil {
				local.Close()
				return err
			}
			if a, err := netip.ParseAddr(ip); err == nil {
				pardonTS[a] = ts
			}
		}
		local.Close()
		for _, e := range pardons {
			if e.TS <= pardonTS[e.IP] {
				continue
			}
			pardonTS[e.IP] = e.TS
			if _, err := tx.Exec(`INSERT INTO pardons (ip, ts) VALUES (?, ?)
				ON CONFLICT(ip) DO UPDATE SET ts = MAX(ts, excluded.ts)`, e.IP.String(), e.TS); err != nil {
				return err
			}
			cur, err := getHost(tx, e.IP)
			if err != nil {
				return err
			}
			if cur != nil && policy.PardonApplies(cur.Record, e.TS) {
				if _, err := tx.Exec(`DELETE FROM hosts WHERE ip = ?`, e.IP.String()); err != nil {
					return err
				}
				res.Pardoned = append(res.Pardoned, e.IP)
				res.Updated++
			}
		}

		for _, e := range perms {
			cur, err := getHost(tx, e.IP)
			if err != nil {
				return err
			}
			var rec *policy.Record
			if cur != nil {
				rec = &cur.Record
			}
			merged, changed := policy.RemotePerm(rec, e.TS, pardonTS[e.IP], now, p)
			if !changed {
				continue
			}
			h := Host{IP: e.IP, Family: ipaddr.Family(e.IP), Record: merged, Source: "sync", UpdatedAt: now}
			if cur != nil {
				h.Source = cur.Source
			}
			if err := putHost(tx, h); err != nil {
				return err
			}
			if cur == nil || !cur.Perm {
				res.NewPerm = append(res.NewPerm, e.IP)
			}
			res.Updated++
		}
		return nil
	})
	return res, err
}
