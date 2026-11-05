package main

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"text/tabwriter"
	"time"

	"gobl/internal/config"
	"gobl/internal/ipaddr"
	"gobl/internal/migrate"
	"gobl/internal/nft"
	"gobl/internal/policy"
	"gobl/internal/store"
	"gobl/internal/syncer"
)

type app struct {
	cfg config.Config
	log *logger
	now func() int64
	nb  nft.Backend
}

func (a *app) params() policy.Params {
	return policy.Params{Timeout: a.cfg.PermabanTimeout, Retry: a.cfg.PermabanRetry, Forgive: a.cfg.PermabanForgive}
}

func (a *app) logEvents() bool { return a.cfg.EventsRetention > 0 }

func (a *app) store() (*store.Store, error) { return store.Open(a.cfg.DBPath) }

func (a *app) nft() (nft.Backend, error) {
	if a.nb != nil {
		return a.nb, nil
	}
	nb, err := nft.New(a.cfg.NftBackend, a.cfg.TableFamily, a.cfg.TableName)
	if err != nil {
		return nil, err
	}
	a.nb = nb
	return nb, nil
}

// setFor returns the temp or perm set for ip's family, or "" if IPv6 is
// disabled.
func (a *app) setFor(ip netip.Addr, perm bool) string {
	switch {
	case ip.Is4() && perm:
		return a.cfg.SetPerm
	case ip.Is4():
		return a.cfg.SetTemp
	case !a.cfg.IPv6Enabled():
		return ""
	case perm:
		return a.cfg.SetPerm6
	default:
		return a.cfg.SetTemp6
	}
}

type setSpec struct {
	name string
	v6   bool
}

func (a *app) allSets() []setSpec {
	sets := []setSpec{{a.cfg.SetTemp, false}, {a.cfg.SetPerm, false}}
	if a.cfg.IPv6Enabled() {
		sets = append(sets, setSpec{a.cfg.SetTemp6, true}, setSpec{a.cfg.SetPerm6, true})
	}
	return sets
}

// groupBySet maps each address to its set; IPv6 addresses are dropped when
// IPv6 is disabled.
func (a *app) groupBySet(ips []netip.Addr, perm bool) map[string][]netip.Addr {
	out := map[string][]netip.Addr{}
	for _, ip := range ips {
		if s := a.setFor(ip, perm); s != "" {
			out[s] = append(out[s], ip)
		}
	}
	return out
}

// addWithEnsure adds to a set, creating the set and retrying once if the
// first attempt fails (rubl checked the sets on every call).
func (a *app) addWithEnsure(nb nft.Backend, set string, v6 bool, ips []netip.Addr) error {
	err := nb.Add(set, ips)
	if err == nil {
		return nil
	}
	if ensureErr := nb.EnsureSet(set, v6); ensureErr != nil {
		return errors.Join(err, ensureErr)
	}
	return nb.Add(set, ips)
}

func parseIP(s string) (netip.Addr, bool) {
	ip, err := ipaddr.Parse(s)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gobl:", err)
		return ip, false
	}
	return ip, true
}

// cmdBan records a ban. A restored ban (fail2ban re-applying its own bans
// after a restart) is not counted again; the IP only goes back into the set
// matching its current state.
func (a *app) cmdBan(arg, jail string, restored bool) int {
	ip, ok := parseIP(arg)
	if !ok {
		return exitUsage
	}

	// Accounting failures must not prevent the ban: fall back to a temp ban.
	perm := false
	if st, err := a.store(); err != nil {
		a.log.Error("ban %s: open db: %v (temp-banning anyway)", ip, err)
	} else {
		if restored {
			h, err := st.Get(ip)
			if err != nil {
				a.log.Error("ban %s: db: %v (temp-banning anyway)", ip, err)
			} else if h != nil {
				perm = h.Perm
			}
		} else {
			h, err := st.Ban(ip, jail, a.now(), a.params(), a.logEvents())
			if err != nil {
				a.log.Error("ban %s: db: %v (temp-banning anyway)", ip, err)
			} else {
				perm = h.Perm
			}
		}
		st.Close()
	}

	set := a.setFor(ip, perm)
	if set == "" {
		a.log.Warn("ban %s: IPv6 sets not configured, recorded in DB only", ip)
		return exitOK
	}
	nb, err := a.nft()
	if err != nil {
		a.log.Error("ban %s: %v", ip, err)
		return exitError
	}
	if err := a.addWithEnsure(nb, set, ip.Is6(), []netip.Addr{ip}); err != nil {
		a.log.Error("ban %s: %v", ip, err)
		return exitError
	}
	a.log.Info("ban %s jail=%q set=%s restored=%v", ip, jail, set, restored)
	return exitOK
}

func (a *app) cmdUnban(arg, jail string) int {
	ip, ok := parseIP(arg)
	if !ok {
		return exitUsage
	}
	set := a.setFor(ip, false)
	if set == "" {
		return exitOK
	}
	nb, err := a.nft()
	if err != nil {
		a.log.Error("unban %s: %v", ip, err)
		return exitError
	}
	if err := nb.Delete(set, []netip.Addr{ip}); err != nil {
		a.log.Error("unban %s: %v", ip, err)
		return exitError
	}
	if a.logEvents() {
		if st, err := a.store(); err == nil {
			if err := st.LogEvent(a.now(), ip, jail, "unban"); err != nil {
				a.log.Warn("unban %s: log event: %v", ip, err)
			}
			st.Close()
		}
	}
	a.log.Info("unban %s jail=%q", ip, jail)
	return exitOK
}

// ensureSets creates missing sets. IPv4 failures are errors; IPv6 failures
// are only warnings so a v6 problem never stops fail2ban.
func (a *app) ensureSets(nb nft.Backend) error {
	for _, s := range a.allSets() {
		if err := nb.EnsureSet(s.name, s.v6); err != nil {
			if s.v6 {
				a.log.Warn("ensure set %s: %v", s.name, err)
				continue
			}
			return err
		}
	}
	return nil
}

// syncPerm adds DB permabans missing from the perm sets and, with
// nft_strict_perm, removes entries the DB does not know.
func (a *app) syncPerm(nb nft.Backend, st *store.Store) error {
	perms, err := st.PermIPs()
	if err != nil {
		return err
	}
	want := a.groupBySet(perms, true)
	var errs []error
	for _, s := range a.allSets() {
		if s.name != a.cfg.SetPerm && s.name != a.cfg.SetPerm6 {
			continue
		}
		have, err := nb.List(s.name)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if add := nft.Missing(want[s.name], have); len(add) > 0 {
			if err := nb.Add(s.name, add); err != nil {
				errs = append(errs, err)
			} else {
				a.log.Info("restored %d permabans into %s", len(add), s.name)
			}
		}
		if a.cfg.StrictPerm {
			if del := nft.Missing(have, want[s.name]); len(del) > 0 {
				if err := nb.Delete(s.name, del); err != nil {
					errs = append(errs, err)
				} else {
					a.log.Info("removed %d unknown entries from %s", len(del), s.name)
				}
			}
		}
	}
	return errors.Join(errs...)
}

func (a *app) cmdInit() int {
	nb, err := a.nft()
	if err != nil {
		a.log.Error("init: %v", err)
		return exitError
	}
	if err := a.ensureSets(nb); err != nil {
		a.log.Error("init: %v", err)
		return exitError
	}
	st, err := a.store()
	if err != nil {
		a.log.Error("init: open db: %v (permabans not restored)", err)
		return exitOK
	}
	defer st.Close()
	if err := a.syncPerm(nb, st); err != nil {
		a.log.Error("init: restore permabans: %v", err)
	}
	return exitOK
}

func (a *app) cmdFlush() int {
	nb, err := a.nft()
	if err != nil {
		a.log.Error("flush: %v", err)
		return exitError
	}
	if err := a.ensureSets(nb); err != nil {
		a.log.Error("flush: %v", err)
		return exitError
	}
	code := exitOK
	for _, s := range a.allSets() {
		if s.name != a.cfg.SetTemp && s.name != a.cfg.SetTemp6 {
			continue
		}
		if err := nb.Flush(s.name); err != nil {
			if s.v6 {
				a.log.Warn("flush: %v", err)
				continue
			}
			a.log.Error("flush: %v", err)
			code = exitError
		}
	}
	return code
}

func (a *app) cmdMaintain() int {
	st, err := a.store()
	if err != nil {
		a.log.Error("maintain: open db: %v", err)
		return exitError
	}
	defer st.Close()
	res, err := st.Maintain(a.now(), a.params(), a.cfg.EventsRetention)
	if err != nil {
		a.log.Error("maintain: %v", err)
		return exitError
	}

	nb, err := a.nft()
	if err != nil {
		a.log.Error("maintain: %v", err)
		return exitError
	}
	if err := a.ensureSets(nb); err != nil {
		a.log.Error("maintain: %v", err)
		return exitError
	}

	var expired, forgiven []netip.Addr
	for _, h := range res.Expired {
		expired = append(expired, h.IP)
	}
	for _, h := range res.Forgiven {
		forgiven = append(forgiven, h.IP)
	}
	var errs []error
	for set, ips := range a.groupBySet(append(expired, forgiven...), false) {
		errs = append(errs, nb.Delete(set, ips))
	}
	for set, ips := range a.groupBySet(forgiven, true) {
		errs = append(errs, nb.Delete(set, ips))
	}
	errs = append(errs, a.syncPerm(nb, st))
	a.log.Info("maintain: kept=%d expired=%d forgiven=%d", res.Kept, len(res.Expired), len(res.Forgiven))
	if err := errors.Join(errs...); err != nil {
		a.log.Error("maintain: %v", err)
		return exitError
	}
	return exitOK
}

func (a *app) cmdSync() int {
	if !a.cfg.SyncEnabled() {
		a.log.Info("sync disabled (redis_url is empty)")
		return exitOK
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	st, err := a.store()
	if err != nil {
		a.log.Error("sync: open db: %v", err)
		return exitError
	}
	defer st.Close()
	r, err := syncer.Dial(ctx, a.cfg)
	if err != nil {
		a.log.Error("sync: %v", err)
		return exitError
	}
	defer r.Close()

	res, err := syncer.Run(ctx, st, r, a.cfg.NodeName, a.now(), a.params())
	if err != nil {
		a.log.Error("sync: %v", err)
		return exitError
	}
	if res.Invalid > 0 {
		a.log.Warn("sync: skipped %d non-IP members in Redis", res.Invalid)
	}

	// Apply to nft: pardoned IPs leave all sets, then the perm sets are
	// brought in line with the DB (which adds the newly synced permabans).
	code := exitOK
	nb, err := a.nft()
	if err == nil {
		err = a.ensureSets(nb)
	}
	if err == nil {
		var errs []error
		for _, perm := range []bool{false, true} {
			for set, ips := range a.groupBySet(res.Merge.Pardoned, perm) {
				errs = append(errs, nb.Delete(set, ips))
			}
		}
		errs = append(errs, a.syncPerm(nb, st))
		err = errors.Join(errs...)
	}
	if err != nil {
		a.log.Error("sync: apply to nft: %v (DB is up to date; next maintain retries)", err)
		code = exitError
	}

	a.log.Info("sync: pushed perm=%d pardon=%d, pulled perm=%d pardon=%d, new perm=%d, pardoned=%d",
		res.PushedPerm, res.PushedPardon, res.PulledPerm, res.PulledPardon,
		len(res.Merge.NewPerm), len(res.Merge.Pardoned))
	return code
}

func (a *app) cmdPardon(arg string) int {
	ip, ok := parseIP(arg)
	if !ok {
		return exitUsage
	}
	st, err := a.store()
	if err != nil {
		a.log.Error("pardon %s: open db: %v", ip, err)
		return exitError
	}
	defer st.Close()
	existed, err := st.Pardon(ip, a.now(), a.logEvents())
	if err != nil {
		a.log.Error("pardon %s: %v", ip, err)
		return exitError
	}
	code := exitOK
	if nb, err := a.nft(); err != nil {
		a.log.Error("pardon %s: %v", ip, err)
		code = exitError
	} else {
		for _, perm := range []bool{false, true} {
			if set := a.setFor(ip, perm); set != "" {
				if err := nb.Delete(set, []netip.Addr{ip}); err != nil {
					a.log.Error("pardon %s: %v", ip, err)
					code = exitError
				}
			}
		}
	}
	if !existed {
		fmt.Printf("%s: no record (removed from sets anyway)\n", ip)
	} else {
		fmt.Printf("%s: pardoned\n", ip)
	}
	a.log.Info("pardon %s", ip)
	return code
}

func fmtTime(ts int64) string {
	if ts == 0 {
		return "-"
	}
	return time.Unix(ts, 0).Format(time.DateTime)
}

func (a *app) cmdShow(arg string) int {
	ip, ok := parseIP(arg)
	if !ok {
		return exitUsage
	}
	st, err := a.store()
	if err != nil {
		a.log.Error("show: %v", err)
		return exitError
	}
	defer st.Close()
	h, err := st.Get(ip)
	if err != nil {
		a.log.Error("show: %v", err)
		return exitError
	}
	if h == nil {
		fmt.Printf("%s: no record\n", ip)
		return exitOK
	}
	shown := policy.Decay(h.Record, a.now(), a.params())
	fmt.Printf("ip:          %s\ncounter:     %d (stored %d)\nperm:        %v (since %s)\nfirst seen:  %s\nlast seen:   %s\nsource:      %s\n",
		h.IP, shown.Counter, h.Counter, h.Perm, fmtTime(h.PermSince), fmtTime(h.FirstSeen), fmtTime(h.LastSeen), h.Source)
	return exitOK
}

func (a *app) cmdList(permOnly bool) int {
	st, err := a.store()
	if err != nil {
		a.log.Error("list: %v", err)
		return exitError
	}
	defer st.Close()
	hosts, err := st.List(permOnly)
	if err != nil {
		a.log.Error("list: %v", err)
		return exitError
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "IP\tCOUNTER\tPERM\tLAST SEEN\tSOURCE")
	for _, h := range hosts {
		fmt.Fprintf(w, "%s\t%d\t%v\t%s\t%s\n", h.IP, h.Counter, h.Perm, fmtTime(h.LastSeen), h.Source)
	}
	w.Flush()
	return exitOK
}

func (a *app) cmdImportYAML(path string) int {
	f, err := os.Open(path)
	if err != nil {
		a.log.Error("import-yaml: %v", err)
		return exitError
	}
	defer f.Close()
	hosts, warnings, err := migrate.ParseRublYAML(f, a.now())
	if err != nil {
		a.log.Error("import-yaml: %v", err)
		return exitError
	}
	for _, w := range warnings {
		a.log.Warn("import-yaml: skipped: %s", w)
	}
	st, err := a.store()
	if err != nil {
		a.log.Error("import-yaml: open db: %v", err)
		return exitError
	}
	defer st.Close()
	inserted, skipped, err := st.Import(hosts)
	if err != nil {
		a.log.Error("import-yaml: %v", err)
		return exitError
	}
	fmt.Printf("imported %d records, %d already present, %d invalid\n", inserted, skipped, len(warnings))
	return exitOK
}
