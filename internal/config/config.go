// Package config loads gobl settings from a key = value file,
// with GOBL_<KEY> environment overrides.
package config

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// DefaultPath is the default config file location.
const DefaultPath = "/etc/gobl/gobl.conf"

// Config holds all gobl settings. Durations are in seconds.
type Config struct {
	PermabanTimeout int64 // decay period
	PermabanRetry   int64 // counter value that triggers a permaban
	PermabanForgive int64 // 0 = never forgive

	TableFamily string
	TableName   string
	SetTemp     string
	SetPerm     string
	SetTemp6    string // empty disables IPv6 nft handling
	SetPerm6    string
	NftBackend  string // netlink | exec
	StrictPerm  bool

	DBPath          string
	EventsRetention int64 // 0 disables event logging
	NodeName        string
	Syslog          bool

	RedisURL      string
	RedisDB       int // -1 = not set, use the database from the URL
	RedisUsername string
	RedisPassword string
	RedisPrefix   string
	RedisTLSCA    string // optional CA bundle for rediss://
}

// Default returns the built-in defaults (the policy defaults match rubl's).
func Default() Config {
	host, err := os.Hostname()
	if err != nil {
		host = "unknown"
	}
	return Config{
		PermabanTimeout: 86400,
		PermabanRetry:   1,
		PermabanForgive: 2629746,
		TableFamily:     "inet",
		TableName:       "filter",
		SetTemp:         "f2b_temp",
		SetPerm:         "f2b_perm",
		SetTemp6:        "f2b_temp6",
		SetPerm6:        "f2b_perm6",
		NftBackend:      "netlink",
		DBPath:          "/var/lib/gobl/gobl.db",
		EventsRetention: 2592000,
		NodeName:        host,
		Syslog:          true,
		RedisDB:         -1,
		RedisPrefix:     "f2b:",
	}
}

// IPv6Enabled reports whether both IPv6 set names are configured.
func (c *Config) IPv6Enabled() bool { return c.SetTemp6 != "" && c.SetPerm6 != "" }

// SyncEnabled reports whether Redis sync is configured.
func (c *Config) SyncEnabled() bool { return c.RedisURL != "" }

// Load reads path (a missing file means all defaults), then applies
// environment overrides. On error it still returns a usable config with
// defaults filled in for anything that could not be parsed.
func Load(path string) (Config, error) {
	cfg := Default()
	var errs []error

	f, err := os.Open(path)
	switch {
	case err == nil:
		defer f.Close()
		errs = append(errs, parse(&cfg, f, path)...)
	case errors.Is(err, os.ErrNotExist):
		// defaults only
	default:
		errs = append(errs, err)
	}

	errs = append(errs, applyEnv(&cfg)...)
	if err := cfg.Validate(); err != nil {
		errs = append(errs, err)
	}
	return cfg, errors.Join(errs...)
}

// Parse reads key = value lines from r into cfg. Exposed for tests.
func Parse(cfg *Config, r io.Reader) error {
	return errors.Join(parse(cfg, r, "<input>")...)
}

func parse(cfg *Config, r io.Reader, name string) []error {
	var errs []error
	sc := bufio.NewScanner(r)
	line := 0
	for sc.Scan() {
		line++
		text := strings.TrimSpace(sc.Text())
		if text == "" || text[0] == '#' || text[0] == ';' {
			continue
		}
		key, val, ok := strings.Cut(text, "=")
		if !ok {
			errs = append(errs, fmt.Errorf("%s:%d: expected key = value", name, line))
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		if err := set(cfg, key, unquote(strings.TrimSpace(val))); err != nil {
			errs = append(errs, fmt.Errorf("%s:%d: %w", name, line, err))
		}
	}
	if err := sc.Err(); err != nil {
		errs = append(errs, fmt.Errorf("%s: %w", name, err))
	}
	return errs
}

func applyEnv(cfg *Config) []error {
	var errs []error
	for _, key := range keys {
		if val, ok := os.LookupEnv("GOBL_" + strings.ToUpper(key)); ok {
			if err := set(cfg, key, val); err != nil {
				errs = append(errs, fmt.Errorf("env GOBL_%s: %w", strings.ToUpper(key), err))
			}
		}
	}
	return errs
}

func unquote(v string) string {
	if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
		return v[1 : len(v)-1]
	}
	return v
}

var keys = []string{
	"permaban_timeout", "permaban_retry", "permaban_forgive",
	"nft_table", "set_temp", "set_perm", "set_temp6", "set_perm6",
	"nft_backend", "nft_strict_perm", "db_path", "events_retention", "node_name", "syslog",
	"redis_url", "redis_db", "redis_username", "redis_password", "redis_prefix", "redis_tls_ca",
}

// set assigns one key. An empty value keeps the default, except for keys
// where empty is meaningful (IPv6 set names, Redis settings).
func set(cfg *Config, key, val string) error {
	def := Default()
	switch key {
	case "permaban_timeout":
		return setInt(&cfg.PermabanTimeout, val, def.PermabanTimeout)
	case "permaban_retry":
		return setInt(&cfg.PermabanRetry, val, def.PermabanRetry)
	case "permaban_forgive":
		if strings.EqualFold(val, "false") {
			cfg.PermabanForgive = 0
			return nil
		}
		return setInt(&cfg.PermabanForgive, val, def.PermabanForgive)
	case "nft_table":
		if val == "" {
			cfg.TableFamily, cfg.TableName = def.TableFamily, def.TableName
			return nil
		}
		fields := strings.Fields(val)
		if len(fields) != 2 {
			return fmt.Errorf("nft_table: want \"<family> <name>\", got %q", val)
		}
		cfg.TableFamily, cfg.TableName = fields[0], fields[1]
	case "set_temp":
		cfg.SetTemp = orDefault(val, def.SetTemp)
	case "set_perm":
		cfg.SetPerm = orDefault(val, def.SetPerm)
	case "set_temp6":
		cfg.SetTemp6 = val
	case "set_perm6":
		cfg.SetPerm6 = val
	case "nft_backend":
		cfg.NftBackend = orDefault(val, def.NftBackend)
	case "nft_strict_perm":
		return setBool(&cfg.StrictPerm, val, def.StrictPerm)
	case "syslog":
		return setBool(&cfg.Syslog, val, def.Syslog)
	case "db_path":
		cfg.DBPath = orDefault(val, def.DBPath)
	case "events_retention":
		return setInt(&cfg.EventsRetention, val, def.EventsRetention)
	case "node_name":
		cfg.NodeName = orDefault(val, def.NodeName)
	case "redis_url":
		cfg.RedisURL = val
	case "redis_db":
		if val == "" {
			cfg.RedisDB = -1
			return nil
		}
		n, err := strconv.Atoi(val)
		if err != nil {
			return fmt.Errorf("redis_db: %w", err)
		}
		cfg.RedisDB = n
	case "redis_username":
		cfg.RedisUsername = val
	case "redis_password":
		cfg.RedisPassword = val
	case "redis_prefix":
		cfg.RedisPrefix = orDefault(val, def.RedisPrefix)
	case "redis_tls_ca":
		cfg.RedisTLSCA = val
	default:
		return fmt.Errorf("unknown key %q", key)
	}
	return nil
}

func setInt(dst *int64, val string, def int64) error {
	if val == "" {
		*dst = def
		return nil
	}
	n, err := strconv.ParseInt(val, 10, 64)
	if err != nil {
		return fmt.Errorf("not an integer: %q", val)
	}
	*dst = n
	return nil
}

func setBool(dst *bool, val string, def bool) error {
	if val == "" {
		*dst = def
		return nil
	}
	b, err := strconv.ParseBool(val)
	if err != nil {
		return fmt.Errorf("not a boolean: %q", val)
	}
	*dst = b
	return nil
}

func orDefault(val, def string) string {
	if val == "" {
		return def
	}
	return val
}

// Validate checks value ranges. Invalid values are reset to defaults so the
// config stays usable, and the problems are reported.
func (c *Config) Validate() error {
	def := Default()
	var errs []error
	if c.PermabanTimeout <= 0 {
		errs = append(errs, fmt.Errorf("permaban_timeout must be > 0, got %d", c.PermabanTimeout))
		c.PermabanTimeout = def.PermabanTimeout
	}
	if c.PermabanRetry < 1 {
		errs = append(errs, fmt.Errorf("permaban_retry must be >= 1, got %d", c.PermabanRetry))
		c.PermabanRetry = def.PermabanRetry
	}
	if c.PermabanForgive < 0 {
		errs = append(errs, fmt.Errorf("permaban_forgive must be >= 0, got %d", c.PermabanForgive))
		c.PermabanForgive = def.PermabanForgive
	}
	if c.EventsRetention < 0 {
		errs = append(errs, fmt.Errorf("events_retention must be >= 0, got %d", c.EventsRetention))
		c.EventsRetention = def.EventsRetention
	}
	switch c.TableFamily {
	case "inet", "ip", "ip6":
	default:
		errs = append(errs, fmt.Errorf("nft_table family must be inet, ip or ip6, got %q", c.TableFamily))
		c.TableFamily = def.TableFamily
	}
	switch c.NftBackend {
	case "netlink", "exec":
	default:
		errs = append(errs, fmt.Errorf("nft_backend must be netlink or exec, got %q", c.NftBackend))
		c.NftBackend = def.NftBackend
	}
	if (c.SetTemp6 == "") != (c.SetPerm6 == "") {
		errs = append(errs, errors.New("set_temp6 and set_perm6 must both be set or both be empty"))
	}
	if c.RedisDB < -1 {
		errs = append(errs, fmt.Errorf("redis_db must be >= 0, got %d", c.RedisDB))
		c.RedisDB = -1
	}
	return errors.Join(errs...)
}
