package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseTypicalConfig(t *testing.T) {
	in := `# Managed by config management
permaban_timeout = 3600
permaban_retry   = 3
permaban_forgive = false

redis_url      =
redis_db       =
redis_username =
redis_password = "p#ss word"
`
	cfg := Default()
	if err := Parse(&cfg, strings.NewReader(in)); err != nil {
		t.Fatal(err)
	}
	if cfg.PermabanTimeout != 3600 || cfg.PermabanRetry != 3 || cfg.PermabanForgive != 0 {
		t.Fatalf("got %+v", cfg)
	}
	if cfg.SyncEnabled() {
		t.Fatal("sync should be disabled with empty redis_url")
	}
	if cfg.RedisPassword != "p#ss word" {
		t.Fatalf("password = %q", cfg.RedisPassword)
	}
}

func TestEmptyValuesKeepDefaults(t *testing.T) {
	cfg := Default()
	if err := Parse(&cfg, strings.NewReader("permaban_timeout =\npermaban_retry=\npermaban_forgive =\n")); err != nil {
		t.Fatal(err)
	}
	d := Default()
	if cfg.PermabanTimeout != d.PermabanTimeout || cfg.PermabanRetry != d.PermabanRetry || cfg.PermabanForgive != d.PermabanForgive {
		t.Fatalf("got %+v", cfg)
	}
}

func TestParseErrors(t *testing.T) {
	for _, in := range []string{"bogus = 1", "permaban_retry = abc", "no equals sign", "nft_table = inet"} {
		cfg := Default()
		if err := Parse(&cfg, strings.NewReader(in)); err == nil {
			t.Errorf("%q: expected error", in)
		}
	}
}

func TestLoadMissingFileAndEnv(t *testing.T) {
	t.Setenv("GOBL_PERMABAN_RETRY", "5")
	cfg, err := Load(filepath.Join(t.TempDir(), "nope.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PermabanRetry != 5 {
		t.Fatalf("retry = %d", cfg.PermabanRetry)
	}
}

func TestLoadBrokenFileStillUsable(t *testing.T) {
	p := filepath.Join(t.TempDir(), "gobl.conf")
	os.WriteFile(p, []byte("permaban_retry = 0\npermaban_timeout = x\nset_temp = my_temp\n"), 0o600)
	cfg, err := Load(p)
	if err == nil {
		t.Fatal("expected error")
	}
	if cfg.PermabanRetry != 1 || cfg.PermabanTimeout != 86400 || cfg.SetTemp != "my_temp" {
		t.Fatalf("got %+v", cfg)
	}
}

func TestTableAndIPv6(t *testing.T) {
	cfg := Default()
	if err := Parse(&cfg, strings.NewReader("nft_table = ip fw\nset_temp6 =\nset_perm6 =\n")); err != nil {
		t.Fatal(err)
	}
	if cfg.TableFamily != "ip" || cfg.TableName != "fw" || cfg.IPv6Enabled() {
		t.Fatalf("got %+v", cfg)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}
