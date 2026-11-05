# gobl

A fail2ban action for nftables that learns from repeat offenders.

fail2ban bans an IP for `bantime` and then forgets it. gobl remembers. It
counts how often each IP gets banned over a longer period, and once an IP
crosses a threshold it moves the IP from a **temporary** set to a
**permanent** one. Permabans survive fail2ban restarts and reboots, are
lifted after a configurable quiet period, and can optionally be shared
between hosts through Redis.

- A single static binary (Go, no cgo). It talks to nftables over netlink
  directly, so a ban takes about 3 ms and forks no processes.
- SQLite in WAL mode. Hundreds of concurrent bans per second are safe:
  each one is an atomic transaction, so no counts are lost.
- IPv4 and IPv6.
- gobl only touches its own sets. **Your ruleset decides what happens to
  traffic from those sets.** gobl never creates tables or rules.
- Optional Redis/Valkey sync of permabans and pardons across hosts. If you
  don't configure it, gobl runs standalone.

## How it works

```
fail2ban ──> gobl ban <ip>
               ├─ counter = counter − (full decay periods since last ban) + 1
               ├─ counter < permaban_retry  → add to f2b_temp  / f2b_temp6
               └─ counter ≥ permaban_retry  → add to f2b_perm  / f2b_perm6
fail2ban ──> gobl unban <ip>   → remove from the temp set (permabans stay)

gobl maintain (hourly) → decay counters, lift permabans that have been quiet
                         for permaban_forgive, resync the perm sets with the DB
```

| Setting | Default | Meaning |
|---|---|---|
| `permaban_timeout` | 86400 (1 day) | Each full period without a ban lowers the counter by 1 |
| `permaban_retry` | 1 | Counter value that makes the ban permanent (1 = the first ban is already permanent) |
| `permaban_forgive` | 2629746 (~1 month) | A permaban is lifted after this long without activity (0 = never) |

For example, with `permaban_retry = 3` and `permaban_timeout = 86400`, an IP
that fail2ban bans three times without a full quiet day between bans gets a
permaban.

## Requirements

- Linux with nftables, and gobl running as root (fail2ban runs actions as root).
- fail2ban 0.10 or newer. Older versions work too, but they don't pass
  `<restored>`, so bans fail2ban re-applies after a restart are counted again.
- To build: Go 1.24 or newer.

## Install

### 1. Install the binary

Download a release (static binaries for `amd64`, `arm64` and `armv7`):

```sh
arch=amd64   # or arm64, armv7
curl -fsSLO https://github.com/madkox/gobl/releases/latest/download/gobl_linux_$arch.tar.gz
curl -fsSLO https://github.com/madkox/gobl/releases/latest/download/SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS
tar xzf gobl_linux_$arch.tar.gz && cd gobl_linux_$arch
sudo install -m 0755 gobl /usr/local/sbin/gobl
```

The archive also contains `packaging/` and the README, so the steps below
work from inside the unpacked directory.

Or build from source:

```sh
make build                      # → bin/gobl (static, linux/amd64)
# GOARCH=arm64 make build       # other architectures
sudo install -m 0755 bin/gobl /usr/local/sbin/gobl
```

Or, with Go installed:

```sh
CGO_ENABLED=0 go install github.com/madkox/gobl/cmd/gobl@latest
sudo install -m 0755 "$(go env GOPATH)/bin/gobl" /usr/local/sbin/gobl
```

### 2. Configuration

```sh
sudo install -d -m 0750 /etc/gobl
sudo install -m 0600 packaging/gobl.conf.example /etc/gobl/gobl.conf
sudo editor /etc/gobl/gobl.conf
sudo gobl check-config
```

gobl reads the file on every run, so changes apply from the next fail2ban
action without a reload. A missing file means all defaults. If the file is
broken, gobl logs the error and still bans, using the defaults for the
invalid values. The full list of keys is under
[Configuration](#configuration).

### 3. nftables rules

Add the sets and drop rules to your ruleset, usually `/etc/nftables.conf`.
A complete example is in `packaging/nftables/gobl-example.nft`. The part
that matters:

```nft
table inet filter {
	set f2b_temp  { type ipv4_addr; }
	set f2b_perm  { type ipv4_addr; }
	set f2b_temp6 { type ipv6_addr; }
	set f2b_perm6 { type ipv6_addr; }

	chain input {
		type filter hook input priority filter; policy drop;
		# whitelist / management access goes BEFORE these rules
		ip  saddr @f2b_temp  drop
		ip  saddr @f2b_perm  drop
		ip6 saddr @f2b_temp6 drop
		ip6 saddr @f2b_perm6 drop
		# ...
	}
}
```

The table must exist. `gobl init` creates any missing sets, but the
`drop` rules are yours to add. Without them, bans are recorded but have no
effect. Sets must be plain sets: no `flags interval` and no timeouts.

To use a different table or other set names, set `nft_table` and `set_*`
in the config.

### 4. fail2ban action

```sh
sudo install -m 0644 packaging/fail2ban/action.d/gobl.conf /etc/fail2ban/action.d/gobl.conf
```

Use it in `/etc/fail2ban/jail.local`, either for all jails:

```ini
[DEFAULT]
banaction = gobl
banaction_allports = gobl
```

or for a single jail:

```ini
[sshd]
enabled = true
action  = gobl[name=sshd]
```

Then restart fail2ban with `sudo systemctl restart fail2ban`. On start,
fail2ban runs `gobl init`, which creates the sets and restores permabans
from the database. On stop, it runs `gobl flush`, which empties the
temporary sets. Permabans stay.

### 5. Schedule maintenance

`gobl maintain` decays counters, lifts expired permabans and repairs the
perm sets. Run it hourly, either with the provided systemd timer:

```sh
sudo install -m 0644 packaging/systemd/gobl-maintain.* /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now gobl-maintain.timer
```

or with cron (`/etc/cron.d/gobl`):

```
17 * * * *  root  /usr/local/sbin/gobl maintain
```

### 6. Check that it works

```sh
sudo gobl ban 192.0.2.1 --jail test     # manual test ban
sudo nft list set inet filter f2b_perm   # with permaban_retry = 1 it is here
sudo gobl show 192.0.2.1
sudo gobl pardon 192.0.2.1               # undo
journalctl -t gobl                       # gobl logs to syslog (daemon facility)
```

## Configuration

`/etc/gobl/gobl.conf` (another path can be given with `gobl -c <file>` or the
`GOBL_CONFIG` env var). The format is `key = value`, one per line. Only
lines that *start* with `#` or `;` are comments, so values such as
passwords may contain `#`. Values may be quoted. An empty value means the
default. Any key can also be overridden with an environment variable
`GOBL_<KEY>`, for example `GOBL_PERMABAN_RETRY=3`.

| Key | Default | Description |
|---|---|---|
| `permaban_timeout` | `86400` | Decay period, in seconds |
| `permaban_retry` | `1` | Counter value that triggers a permaban |
| `permaban_forgive` | `2629746` | Quiet period, in seconds, before a permaban is lifted. `0`/`false` = never |
| `nft_table` | `inet filter` | `<family> <name>`. The family is `inet`, `ip` or `ip6` |
| `set_temp`, `set_perm` | `f2b_temp`, `f2b_perm` | IPv4 sets |
| `set_temp6`, `set_perm6` | `f2b_temp6`, `f2b_perm6` | IPv6 sets. Set both empty to keep IPv6 bans in the DB only |
| `nft_backend` | `netlink` | `netlink`, or `exec` to run the `nft` binary instead |
| `nft_strict_perm` | `false` | If true, `maintain` also removes perm-set entries that aren't in the DB |
| `db_path` | `/var/lib/gobl/gobl.db` | SQLite database. The directory is created if missing |
| `events_retention` | `2592000` | Seconds to keep the ban/unban audit log. `0` = no log |
| `syslog` | `true` | Log to syslog (tag `gobl`). Errors also go to stderr |
| `node_name` | hostname | This host's name in the sync heartbeat |
| `redis_url` | empty | `redis://`, `rediss://` (TLS) or `unix://`. Empty = no sync |
| `redis_db`, `redis_username`, `redis_password` | empty | Override the matching parts of the URL |
| `redis_tls_ca` | empty | CA bundle (PEM) for `rediss://` |
| `redis_prefix` | `f2b:` | Prefix for the Redis keys |

## Commands

| Command | Description |
|---|---|
| `gobl init` | Create missing sets and restore permabans from the DB (fail2ban `actionstart`) |
| `gobl flush` | Flush the temporary sets (fail2ban `actionstop`) |
| `gobl ban <ip> [--jail name] [--restored 0\|1]` | Record a ban and add the IP to the temp or perm set |
| `gobl unban <ip> [--jail name]` | Remove the IP from the temp set |
| `gobl maintain` | Decay, forgive, resync the perm sets, prune the audit log |
| `gobl sync` | Exchange permabans and pardons with Redis. Does nothing if `redis_url` is empty |
| `gobl show <ip>` | Show the record for an IP |
| `gobl list [--perm]` | List all records, or only permabans |
| `gobl pardon <ip>` | Remove an IP from all sets and forget its history (propagated by sync) |
| `gobl import-yaml <file>` | Import a `list.yml` from rubl, gobl's Ruby predecessor |
| `gobl check-config [file]` | Validate a config file |
| `gobl version` | Print the version |

Global flags: `-c <file>` sets the config file, and `-v` also prints info
messages to stderr.

Exit codes: `0` for success, `1` for a runtime error, `2` for bad usage or
an invalid IP. Errors are written to stderr, so fail2ban shows them in its
log.

**Failure behavior:**

- If the database is unavailable, `ban` still adds the IP to the temp set.
- If the config is broken, gobl uses the defaults for the invalid values.
- A ban is never dropped silently.

## Sharing permabans between hosts (optional)

Point every host at the same Redis 6.2+ (or Valkey) instance:

```ini
redis_url      = rediss://redis.example.net:6380
redis_db       = 0
redis_username = gobl
redis_password = secret
```

Then run `gobl sync` periodically, for example daily with the provided timer:

```sh
sudo install -m 0644 packaging/systemd/gobl-sync.* /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now gobl-sync.timer
```

**What each sync does:**

1. Pushes all local permabans and pardons.
2. Pulls everything newer than the forgive period.
3. Merges, using the newer timestamp when both sides know an IP.
4. Applies the result to the nft sets.

A pardon on one host removes the IP everywhere, unless the IP was banned
again after the pardon.

**Redis keys:**

- `f2b:perm` and `f2b:pardon`: sorted sets with the timestamp as score.
- `f2b:nodes`: a hash of host → last successful sync, useful for monitoring
  (`redis-cli hgetall f2b:nodes`).

**Minimal ACL:**

```
user gobl on >secret ~f2b:* +@all
```

**Things to keep in mind:**

- Keep the hosts' clocks NTP-synced.
- Use the same `permaban_forgive` on every host.
- If Redis is down, `sync` fails with exit 1. Banning is unaffected,
  because the ban path never touches the network.

## Operations

- **Whitelisting:** use fail2ban's `ignoreip` so gobl is never called for
  those IPs, and put accept rules for management access before the `f2b_*`
  drop rules.
- **After a reboot or ruleset reload:** the sets start empty. fail2ban's
  start (`gobl init`) restores permabans, and so does the next
  `gobl maintain`. If you reload nftables while fail2ban keeps running, run
  `gobl init` afterwards.
- **Fixing a false positive:** `gobl pardon <ip>`. Also run
  `fail2ban-client set <jail> unbanip <ip>` if fail2ban still holds a
  temporary ban.
- **Inspecting the data:** besides `gobl show` and `gobl list`, the
  database can be queried with
  `sqlite3 /var/lib/gobl/gobl.db 'SELECT * FROM events ORDER BY ts DESC LIMIT 20'`.

## Migrating from rubl

1. Run `gobl import-yaml /etc/bfw/list.yml` once, *before* switching the jails.
2. Switch the jails to `banaction = gobl`.
3. Replace the `rubl maintain` cron job with `gobl maintain`. Don't run
   both: rubl would re-add permabans gobl has already lifted.

The command-line interface, set names and exit codes are the same as
rubl's.

## Development

```sh
make test          # unit tests
make integration   # real binary against nftables in a throwaway network namespace
make dist          # release archives for all architectures into dist/
```

Releases are built by GitHub Actions (`.github/workflows/release.yml`) when
a `v*` tag is pushed. A tag containing `-` (e.g. `v0.2.0-rc1`) is marked as a
pre-release.

The integration suite needs `unshare` (it runs unprivileged), `nft` and
`sqlite3`. It covers both nft backends. With `redis-server` and
`redis-cli` installed, it also runs a two-host sync scenario. It never
touches the host's firewall.

Code layout:

```
cmd/gobl/          CLI
internal/config    config file parser and validation
internal/policy    decay / threshold / forgive / merge rules (pure functions)
internal/store     SQLite schema and transactions
internal/nft       netlink and nft-exec backends
internal/syncer    Redis sync
internal/migrate   rubl YAML import
packaging/         fail2ban action, example config, systemd units, nft example
```

## Uninstall

```sh
sudo systemctl disable --now gobl-maintain.timer gobl-sync.timer
# switch jails back to another banaction, restart fail2ban, then:
sudo rm /usr/local/sbin/gobl /etc/fail2ban/action.d/gobl.conf /etc/systemd/system/gobl-*
sudo rm -r /etc/gobl /var/lib/gobl
sudo nft delete set inet filter f2b_temp   # and the other f2b_* sets, after removing their rules
```

## License

MIT. See [LICENSE](LICENSE).
