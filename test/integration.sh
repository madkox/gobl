#!/bin/sh
# Integration test: runs the real gobl binary against nftables inside a
# throwaway user + network namespace (no root needed, host firewall untouched).
#
#   test/integration.sh [path/to/gobl]
#
# Runs every scenario once per nft backend (netlink, exec).
set -eu

GOBL=$(realpath "${1:-bin/gobl}")

if [ "${GOBL_IN_NS:-}" != 1 ]; then
	exec env GOBL_IN_NS=1 unshare -rn sh "$0" "$GOBL"
fi

command -v sqlite3 >/dev/null || { echo "sqlite3 is required"; exit 1; }

FAILS=0
pass() { printf '  ok   %s\n' "$1"; }
fail() { printf '  FAIL %s\n' "$1"; FAILS=$((FAILS + 1)); }
check() { # check <description> <command...>
	desc=$1; shift
	if "$@" >/dev/null 2>&1; then pass "$desc"; else fail "$desc"; fi
}
in_set() { nft list set inet filter "$1" | grep -qw -- "$2"; }
not_in_set() { ! in_set "$1" "$2"; }
set_empty() { ! nft list set inet filter "$1" | grep -q elements; }
exit_code() { # exit_code <expected> <command...>
	want=$1; shift
	set +e; "$@" >/dev/null 2>&1; got=$?; set -e
	[ "$got" = "$want" ]
}

run_suite() {
	backend=$1
	echo "== backend: $backend"
	WORK=$(mktemp -d)
	export GOBL_CONFIG="$WORK/gobl.conf"
	cat >"$GOBL_CONFIG" <<-EOF
		# typical config
		permaban_timeout = 86400
		permaban_retry   = 3
		permaban_forgive = 2629746
		db_path          = $WORK/gobl.db
		nft_backend      = $backend
		syslog           = false
		redis_url        =
	EOF
	DB="$WORK/gobl.db"

	nft flush ruleset
	nft -f - <<-'EOF'
		table inet filter {
			set f2b_temp { type ipv4_addr; }
			set f2b_perm { type ipv4_addr; }
			chain input {
				type filter hook input priority filter; policy accept;
				ip saddr @f2b_temp drop
				ip saddr @f2b_perm drop
			}
		}
	EOF

	check "check-config accepts rendered config" "$GOBL" check-config "$GOBL_CONFIG"
	printf 'permaban_retry = zero\n' >"$WORK/bad.conf"
	check "check-config rejects broken config" exit_code 1 "$GOBL" check-config "$WORK/bad.conf"
	check "no command exits 2" exit_code 2 "$GOBL"
	check "invalid IP exits 2" exit_code 2 "$GOBL" ban '1.2.3.4; reboot'

	check "init" "$GOBL" init
	check "init created v6 sets" nft list set inet filter f2b_perm6

	"$GOBL" ban 1.2.3.4 --jail sshd
	check "1st ban -> temp" in_set f2b_temp 1.2.3.4
	check "1st ban -> not perm" not_in_set f2b_perm 1.2.3.4
	"$GOBL" ban 1.2.3.4 sshd
	"$GOBL" ban 1.2.3.4
	check "3rd ban (retry=3) -> perm" in_set f2b_perm 1.2.3.4

	"$GOBL" ban 2001:db8::1
	check "v6 ban -> temp6" in_set f2b_temp6 2001:db8::1
	"$GOBL" ban ::ffff:5.6.7.8
	check "v4-mapped normalized to v4" in_set f2b_temp 5.6.7.8

	"$GOBL" ban 9.8.7.6 --restored 1
	"$GOBL" ban 9.8.7.6 --jail sshd --restored 1
	"$GOBL" ban 9.8.7.6 --restored '<restored>'
	check "restored bans are not counted (got $(sqlite3 "$DB" "SELECT counter FROM hosts WHERE ip='9.8.7.6'"))" \
		[ "$(sqlite3 "$DB" "SELECT counter FROM hosts WHERE ip='9.8.7.6'")" = 1 ]
	check "restored ban -> temp" in_set f2b_temp 9.8.7.6

	"$GOBL" unban 1.2.3.4
	check "unban removes from temp" not_in_set f2b_temp 1.2.3.4
	check "unban keeps perm" in_set f2b_perm 1.2.3.4
	check "unban of absent IP succeeds" "$GOBL" unban 9.9.9.9

	GOBL_PERMABAN_RETRY=1 "$GOBL" ban 7.7.7.7
	check "retry=1 -> first ban is perm" in_set f2b_perm 7.7.7.7

	# Concurrency: 400 bans over 8 IPs from 32 parallel processes.
	seq 1 400 | xargs -P 32 -I{} sh -c '"$0" ban "10.0.0.$(( {} % 8 + 1 ))"' "$GOBL"
	total=$(sqlite3 "$DB" "SELECT SUM(counter) FROM hosts WHERE ip LIKE '10.0.0.%'")
	check "400 concurrent bans, no lost updates (got $total)" [ "$total" = 400 ]

	check "flush" "$GOBL" flush
	check "flush empties temp" set_empty f2b_temp
	check "flush empties temp6" set_empty f2b_temp6
	check "flush keeps perm" in_set f2b_perm 1.2.3.4

	nft flush set inet filter f2b_perm
	"$GOBL" init
	check "init restores permabans after reboot" in_set f2b_perm 1.2.3.4

	# Time travel: make records old, then maintain.
	"$GOBL" ban 20.0.0.1
	sqlite3 "$DB" "UPDATE hosts SET decay_anchor = decay_anchor - 86400 WHERE ip = '20.0.0.1';
	               UPDATE hosts SET last_seen = last_seen - 3000000 WHERE ip = '1.2.3.4';"
	check "maintain" "$GOBL" maintain
	check "decayed record removed from temp" not_in_set f2b_temp 20.0.0.1
	check "decayed record deleted" [ -z "$(sqlite3 "$DB" "SELECT ip FROM hosts WHERE ip='20.0.0.1'")" ]
	check "forgiven IP removed from perm set" not_in_set f2b_perm 1.2.3.4
	check "other perm kept" in_set f2b_perm 7.7.7.7

	nft add element inet filter f2b_perm '{ 8.8.4.4 }'
	"$GOBL" maintain
	check "non-strict maintain keeps manual perm entry" in_set f2b_perm 8.8.4.4
	GOBL_NFT_STRICT_PERM=true "$GOBL" maintain
	check "strict maintain removes unknown perm entry" not_in_set f2b_perm 8.8.4.4

	check "pardon" "$GOBL" pardon 7.7.7.7
	check "pardon removes from perm" not_in_set f2b_perm 7.7.7.7

	cat >"$WORK/list.yml" <<-'EOF'
		---
		30.0.0.1:
		  :counter: 5
		  :permaban: true
		  :timestamp: 1999999999
		30.0.0.2:
		  :counter: 1
		  :permaban: false
		  :timestamp: 1999999999
	EOF
	check "import-yaml" "$GOBL" import-yaml "$WORK/list.yml"
	"$GOBL" init
	check "imported permaban applied by init" in_set f2b_perm 30.0.0.1
	check "show" "$GOBL" show 30.0.0.2
	check "list --perm" "$GOBL" list --perm
	check "sync disabled exits 0" "$GOBL" sync

	# Failure paths: a ban must still happen.
	GOBL_CONFIG="$WORK/bad.conf" GOBL_DB_PATH="$DB" GOBL_SYSLOG=false GOBL_NFT_BACKEND=$backend \
		"$GOBL" ban 40.0.0.1 2>/dev/null
	check "broken config still bans" in_set f2b_perm 40.0.0.1
	GOBL_DB_PATH=/proc/nope/gobl.db "$GOBL" ban 40.0.0.2 2>/dev/null
	check "unusable DB still temp-bans" in_set f2b_temp 40.0.0.2

	rm -rf "$WORK"
}


# Two simulated hosts (separate DB, separate nft table) syncing through a
# real redis-server with an ACL user, password and non-zero DB number.
run_sync_suite() {
	echo "== redis sync"
	if ! command -v redis-server >/dev/null || ! command -v redis-cli >/dev/null; then
		echo "  skip (redis-server not installed)"
		return
	fi
	WORK=$(mktemp -d)
	ip link set lo up
	PORT=16379
	cat >"$WORK/redis.conf" <<-EOF
		port $PORT
		bind 127.0.0.1
		save ""
		appendonly no
		user default off
		user gobl on >s3cret ~f2b:* &* +@all
	EOF
	redis-server "$WORK/redis.conf" >"$WORK/redis.log" 2>&1 &
	RPID=$!
	for _ in 1 2 3 4 5 6 7 8 9 10; do
		redis-cli -p $PORT --user gobl --pass s3cret ping >/dev/null 2>&1 && break
		sleep 0.2
	done
	rcli() { redis-cli -p $PORT --user gobl --pass s3cret -n 5 --no-auth-warning "$@"; }

	nft flush ruleset
	for host in a b; do
		nft add table inet "host_$host"
		cat >"$WORK/$host.conf" <<-EOF
			permaban_retry   = 1
			permaban_forgive = 2629746
			nft_table        = inet host_$host
			db_path          = $WORK/$host.db
			node_name        = host-$host
			syslog           = false
			redis_url        = redis://127.0.0.1:$PORT
			redis_db         = 5
			redis_username   = gobl
			redis_password   = s3cret
		EOF
	done
	A() { GOBL_CONFIG="$WORK/a.conf" "$GOBL" "$@"; }
	B() { GOBL_CONFIG="$WORK/b.conf" "$GOBL" "$@"; }
	in_tbl() { nft list set inet "host_$1" "$2" | grep -qw -- "$3"; }
	not_in_tbl() { ! in_tbl "$@"; }

	A init; B init
	A ban 50.0.0.1
	B ban 2001:db8::50
	check "A sync" A sync
	check "B sync" B sync
	check "A sync again" A sync
	check "B got A's permaban in its perm set" in_tbl b f2b_perm 50.0.0.1
	check "A got B's IPv6 permaban in perm6 set" in_tbl a f2b_perm6 2001:db8::50
	check "redis holds 2 perms in db 5" [ "$(rcli zcard f2b:perm)" = 2 ]
	check "redis nodes hash has both hosts" [ "$(rcli hlen f2b:nodes)" = 2 ]
	check "synced record marked source=sync" [ "$(sqlite3 "$WORK/b.db" "SELECT source FROM hosts WHERE ip='50.0.0.1'")" = sync ]

	sleep 1 # pardon must be newer than the ban (1 s resolution)
	B pardon 50.0.0.1 >/dev/null
	B sync; A sync
	check "pardon on B removed IP from A's perm set" not_in_tbl a f2b_perm 50.0.0.1
	B sync
	check "pardoned IP not resurrected on B" not_in_tbl b f2b_perm 50.0.0.1

	A flush
	nft flush set inet host_a f2b_perm6
	check "sync is idempotent and re-applies perm sets" A sync
	check "perm set repaired by sync" in_tbl a f2b_perm6 2001:db8::50

	check "wrong password: sync exits 1" exit_code 1 env GOBL_REDIS_PASSWORD=wrong GOBL_CONFIG="$WORK/a.conf" "$GOBL" sync
	check "wrong password: bans still work" A ban 60.0.0.1
	kill $RPID; wait $RPID 2>/dev/null || true
	check "redis down: sync exits 1" exit_code 1 A sync
	check "redis down: bans still work" A ban 60.0.0.2
	check "redis down: banned IP in perm set" in_tbl a f2b_perm 60.0.0.2

	rm -rf "$WORK"
}

run_suite netlink
run_suite exec
run_sync_suite

if [ "$FAILS" -gt 0 ]; then
	echo "$FAILS check(s) failed"
	exit 1
fi
echo "all checks passed"
