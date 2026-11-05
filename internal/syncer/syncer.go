// Package syncer shares permabans and pardons between hosts through Redis.
//
// Redis holds two sorted sets (prefix configurable):
//
//	f2b:perm    member = IP, score = last time any host saw it (permabanned)
//	f2b:pardon  member = IP, score = pardon time
//
// plus a hash f2b:nodes (node name -> last successful sync) for monitoring.
//
// Every sync pushes all local entries with ZADD GT (keeps the newest
// score, so pushes are idempotent and order-independent), pulls the whole
// active window, and merges it locally. A full pull is deliberate: pushes
// lag behind bans by up to a sync interval, so an "only newer than my last
// pull" cursor would miss entries. The window is bounded by the forgive
// period, and once a day this is cheap even for 100k+ IPs.
package syncer

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"

	"gobl/internal/config"
	"gobl/internal/ipaddr"
	"gobl/internal/policy"
	"gobl/internal/store"
)

const (
	chunk      = 1000  // members per ZADD
	pageSize   = 10000 // members per ZRANGE page
	mergeChunk = 5000  // remote perms merged per DB transaction
)

// Redis is the sync transport.
type Redis struct {
	c      *redis.Client
	prefix string
}

// Options builds go-redis options from the config. Separate settings
// override what the URL contains.
func Options(cfg config.Config) (*redis.Options, error) {
	if cfg.RedisURL == "" {
		return nil, errors.New("redis_url is empty")
	}
	opts, err := redis.ParseURL(cfg.RedisURL)
	if err != nil {
		return nil, fmt.Errorf("redis_url: %w", err)
	}
	if cfg.RedisDB >= 0 {
		opts.DB = cfg.RedisDB
	}
	if cfg.RedisUsername != "" {
		opts.Username = cfg.RedisUsername
	}
	if cfg.RedisPassword != "" {
		opts.Password = cfg.RedisPassword
	}
	if cfg.RedisTLSCA != "" {
		if opts.TLSConfig == nil {
			return nil, errors.New("redis_tls_ca requires a rediss:// URL")
		}
		pem, err := os.ReadFile(cfg.RedisTLSCA)
		if err != nil {
			return nil, fmt.Errorf("redis_tls_ca: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("redis_tls_ca: no certificates in %s", cfg.RedisTLSCA)
		}
		opts.TLSConfig.RootCAs = pool
	}
	if opts.TLSConfig != nil && opts.TLSConfig.MinVersion == 0 {
		opts.TLSConfig.MinVersion = tls.VersionTLS12
	}
	opts.DialTimeout = 5 * time.Second
	opts.ReadTimeout = 30 * time.Second
	opts.WriteTimeout = 30 * time.Second
	opts.PoolSize = 1
	opts.MaxRetries = 2
	opts.DisableIdentity = true // no CLIENT SETINFO; works with older servers and strict ACLs
	return opts, nil
}

// quietLogger drops go-redis internal log lines; gobl reports the
// resulting errors itself.
type quietLogger struct{}

func (quietLogger) Printf(context.Context, string, ...any) {}

func init() { redis.SetLogger(quietLogger{}) }

// Dial connects and checks the connection.
func Dial(ctx context.Context, cfg config.Config) (*Redis, error) {
	opts, err := Options(cfg)
	if err != nil {
		return nil, err
	}
	c := redis.NewClient(opts)
	if err := c.Ping(ctx).Err(); err != nil {
		c.Close()
		return nil, fmt.Errorf("redis %s: %w", opts.Addr, err)
	}
	return &Redis{c: c, prefix: cfg.RedisPrefix}, nil
}

// Close closes the connection.
func (r *Redis) Close() error { return r.c.Close() }

func (r *Redis) permKey() string   { return r.prefix + "perm" }
func (r *Redis) pardonKey() string { return r.prefix + "pardon" }
func (r *Redis) nodesKey() string  { return r.prefix + "nodes" }

// push adds entries with ZADD GT, pipelined in chunks.
func (r *Redis) push(ctx context.Context, key string, es []store.Entry) error {
	if len(es) == 0 {
		return nil
	}
	pipe := r.c.Pipeline()
	for start := 0; start < len(es); start += chunk {
		part := es[start:min(start+chunk, len(es))]
		members := make([]redis.Z, len(part))
		for i, e := range part {
			members[i] = redis.Z{Score: float64(e.TS), Member: e.IP.String()}
		}
		pipe.ZAddGT(ctx, key, members...)
	}
	_, err := pipe.Exec(ctx)
	return err
}

// pull returns all members with score > after (after <= 0 means all).
// Members that are not valid IPs are skipped and counted.
func (r *Redis) pull(ctx context.Context, key string, after int64) ([]store.Entry, int, error) {
	minScore := "-inf"
	if after > 0 {
		minScore = "(" + strconv.FormatInt(after, 10)
	}
	var out []store.Entry
	invalid := 0
	for offset := int64(0); ; offset += pageSize {
		page, err := r.c.ZRangeArgsWithScores(ctx, redis.ZRangeArgs{
			Key: key, Start: minScore, Stop: "+inf", ByScore: true, Offset: offset, Count: pageSize,
		}).Result()
		if err != nil {
			return nil, 0, err
		}
		for _, z := range page {
			s, _ := z.Member.(string)
			ip, err := ipaddr.Parse(s)
			if err != nil {
				invalid++
				continue
			}
			out = append(out, store.Entry{IP: ip, TS: int64(z.Score)})
		}
		if len(page) < pageSize {
			return out, invalid, nil
		}
	}
}

// Result summarizes one sync run.
type Result struct {
	PushedPerm, PushedPardon int
	PulledPerm, PulledPardon int
	Invalid                  int // non-IP members found in Redis and skipped
	Merge                    store.MergeResult
}

// Run performs one sync cycle: push, pull, merge, trim, heartbeat.
func Run(ctx context.Context, st *store.Store, r *Redis, node string, now int64, p policy.Params) (Result, error) {
	var res Result

	perms, err := st.PermEntries()
	if err != nil {
		return res, err
	}
	pardons, err := st.Pardons()
	if err != nil {
		return res, err
	}
	if err := r.push(ctx, r.permKey(), perms); err != nil {
		return res, fmt.Errorf("push perm: %w", err)
	}
	if err := r.push(ctx, r.pardonKey(), pardons); err != nil {
		return res, fmt.Errorf("push pardon: %w", err)
	}
	res.PushedPerm, res.PushedPardon = len(perms), len(pardons)

	var window int64 // entries older than the forgive period are irrelevant
	if p.Forgive > 0 {
		window = now - p.Forgive
	}
	remotePerm, bad1, err := r.pull(ctx, r.permKey(), window)
	if err != nil {
		return res, fmt.Errorf("pull perm: %w", err)
	}
	remotePardon, bad2, err := r.pull(ctx, r.pardonKey(), window)
	if err != nil {
		return res, fmt.Errorf("pull pardon: %w", err)
	}
	res.PulledPerm, res.PulledPardon, res.Invalid = len(remotePerm), len(remotePardon), bad1+bad2

	// Merge pardons first, then perms in chunks: each chunk is its own
	// short transaction, so concurrent bans never wait long for the lock.
	if res.Merge, err = st.Merge(nil, remotePardon, now, p); err != nil {
		return res, fmt.Errorf("merge: %w", err)
	}
	for start := 0; start < len(remotePerm); start += mergeChunk {
		m, err := st.Merge(remotePerm[start:min(start+mergeChunk, len(remotePerm))], nil, now, p)
		if err != nil {
			return res, fmt.Errorf("merge: %w", err)
		}
		res.Merge.NewPerm = append(res.Merge.NewPerm, m.NewPerm...)
		res.Merge.Updated += m.Updated
	}

	if window > 0 {
		pipe := r.c.Pipeline()
		maxScore := "(" + strconv.FormatInt(window, 10)
		pipe.ZRemRangeByScore(ctx, r.permKey(), "-inf", maxScore)
		pipe.ZRemRangeByScore(ctx, r.pardonKey(), "-inf", maxScore)
		if _, err := pipe.Exec(ctx); err != nil {
			return res, fmt.Errorf("trim: %w", err)
		}
	}
	if err := r.c.HSet(ctx, r.nodesKey(), node, now).Err(); err != nil {
		return res, fmt.Errorf("heartbeat: %w", err)
	}
	return res, nil
}
