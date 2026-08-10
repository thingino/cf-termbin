#!/usr/bin/env bash
# Browser tests for the admin page, in both auth modes that have a login.
#
# tests/smoke.sh covers the Worker; this covers web/, where the interesting failure is not
# a status code but a credential going to the wrong origin. The page is served the way it is
# in production: a plain static server stands in for GitHub Pages, and the Worker proxies it
# at /admin/ on its own origin, so the browser sees one origin and the shipped CSP applies
# unmodified. There is no bespoke dev proxy any more; the Worker does that job for real.
#
#   tests/web.sh                  both modes
#   tests/web.sh token            just one
#   tests/web.sh --serve          start the same stack and leave it up, for hand testing
#   tests/web.sh --serve token    the same, in token mode
#
# Skips cleanly if playwright is not resolvable, since it is not a dependency of this
# project: it pulls a browser download, and the Worker tests must stay installable
# without one.
set -eu
cd "$(dirname "$0")/.."

API_PORT="${API_PORT:-8795}"
WEB_PORT="${WEB_PORT:-8085}"   # stands in for GitHub Pages
ADMIN_KEY="${ADMIN_KEY:-self-hosted-key}"
SESSION="${SESSION:-localsession}"
WORK="$(mktemp -d)"
PASS_TOTAL=0
FAIL_TOTAL=0

API_PID=""
WEB_PID=""
# `disown` after each start, so tearing a server down does not print bash's own
# "Killed" job notice in the middle of the results.
kill_tree() { local p=$1 c; for c in $(pgrep -P "$p" 2>/dev/null); do kill_tree "$c"; done; kill -9 "$p" 2>/dev/null || true; }
cleanup() {
	[ -n "$WEB_PID" ] && kill_tree "$WEB_PID"
	[ -n "$API_PID" ] && kill_tree "$API_PID"
	rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

start_stack() { # start_stack <extra wrangler args...>
	npx wrangler dev --port "$API_PORT" --persist-to "${WORK}/state" \
		--var PORTAL_UPSTREAM:"http://127.0.0.1:${WEB_PORT}" "$@" >"${WORK}/wrangler.log" 2>&1 &
	API_PID=$!
	disown "$API_PID" 2>/dev/null || true
	curl -s -o /dev/null -m 10 --retry 90 --retry-delay 1 --retry-connrefused "http://127.0.0.1:${API_PORT}/robots.txt" \
		|| { echo "wrangler dev did not start:"; tail -20 "${WORK}/wrangler.log"; exit 1; }
	# A report, so the list has something in it and an empty table cannot pass for a
	# working session.
	printf 'web test\nordinary log line\n' \
		| curl -s -o /dev/null -H 'X-Thingino-Client: cpe:/o:thinginoproject:thingino:1' \
			--data-binary @- "http://127.0.0.1:${API_PORT}/"
	curl -s -o /dev/null -m 10 --retry 60 --retry-delay 1 --retry-connrefused "http://127.0.0.1:${API_PORT}/admin/" \
		|| { echo "the Worker never served the portal:"; tail -20 "${WORK}/wrangler.log"; exit 1; }
}

# Stands in for GitHub Pages. Started once, before any Worker, because PORTAL_UPSTREAM has
# to point at something that is already listening.
start_pages() {
	python3 -m http.server "$WEB_PORT" --bind 127.0.0.1 --directory web >"${WORK}/pages.log" 2>&1 &
	WEB_PID=$!
	disown "$WEB_PID" 2>/dev/null || true
	# Content-checked, not just reachable: a fixed port can already be held by something
	# unrelated on the same host, and then the Worker proxies that instead with everything
	# apparently fine.
	curl -s -m 10 --retry 60 --retry-delay 1 --retry-connrefused "http://127.0.0.1:${WEB_PORT}/index.html" \
		| grep -q 'Diagnostics Bin Admin' \
		|| { echo "port ${WEB_PORT} is not serving web/ (already in use?):"; tail -20 "${WORK}/pages.log"; exit 1; }
}

stop_stack() {
	[ -n "$API_PID" ] && kill_tree "$API_PID"
	API_PID=""
	rm -rf "${WORK}/state"
}

tally() { # tally <output-file>
	local p f
	p="$(sed -n 's/^passed: \([0-9]*\).*/\1/p' "$1" | tail -1)"
	f="$(sed -n 's/.*failed: \([0-9]*\)/\1/p' "$1" | tail -1)"
	PASS_TOTAL=$((PASS_TOTAL + ${p:-0}))
	FAIL_TOTAL=$((FAIL_TOTAL + ${f:-0}))
}

# The bin verifies sessions against the builder's table, so seed one it will accept. Shared
# by the builder-mode run and by --serve. They were separate scripts once, and two copies of
# this plus two copies of start/stop meant a fix to one silently missed the other.
seed_builder_session() {
	mkdir -p "${WORK}/state"
	npx wrangler d1 execute thingino-builder --local --persist-to "${WORK}/state" --command "
	  CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, admin TEXT, expires INTEGER NOT NULL, last_active INTEGER NOT NULL DEFAULT 0);
	  CREATE TABLE IF NOT EXISTS admins (username TEXT PRIMARY KEY, pw_hash TEXT, totp_secret TEXT, disabled INTEGER NOT NULL DEFAULT 0);
	  INSERT OR REPLACE INTO admins (username,totp_secret,disabled) VALUES ('local','x',0);
	  INSERT OR REPLACE INTO sessions (token,admin,expires,last_active)
	    VALUES ('$(printf '%s' "$SESSION" | sha256sum | cut -d' ' -f1)','local',$(($(date +%s) + 28800)),$(date +%s));" >/dev/null
}

run_mode() { # run_mode <token|builder>
	local mode="$1" out="${WORK}/${1}.out"
	echo
	echo "=== ${mode} mode"
	if [ "$mode" = token ]; then
		start_stack --var AUTH_MODE:token --var ADMIN_KEY:"$ADMIN_KEY"
	else
		seed_builder_session
		start_stack
	fi

	UI="http://127.0.0.1:${API_PORT}" MODE="$mode" ADMIN_KEY="$ADMIN_KEY" SESSION="$SESSION" \
		node tests/web.mjs 2>&1 | tee "$out" || true
	if grep -q 'SKIP playwright' "$out"; then
		stop_stack
		echo
		echo "skipped: playwright not available"
		exit 0
	fi
	tally "$out"
	stop_stack
}

# --serve leaves the stack up instead of asserting against it, for driving the admin page by
# hand. Same start_stack, same seeding, same teardown as the suite, so there is one
# implementation of the awkward parts rather than two that drift.
if [ "${1:-}" = "--serve" ]; then
	start_pages
	case "${2:-builder}" in
	token) start_stack --var AUTH_MODE:token --var ADMIN_KEY:"$ADMIN_KEY"
	       echo; echo "  admin key   : ${ADMIN_KEY}" ;;
	*)     seed_builder_session; start_stack
	       # The gate asks the builder for a session, and there is no builder here. Pasting a raw
	       # session into the page was possible once and is not any more, deliberately, so hand
	       # testing seeds it directly.
	       echo; echo "  seeded session: ${SESSION}"
	       echo "  to sign in, run this in the console then reload:"
	       echo "    sessionStorage.setItem('tb_admin_session','${SESSION}')" ;;
	esac
	echo "  admin portal : http://127.0.0.1:${API_PORT}/admin/   (served by the Worker)"
	echo "  API          : http://127.0.0.1:${API_PORT}"
	echo "  Ctrl-C to stop"
	# Not `wait`: start_stack disowns the job, so waiting on it fails immediately and the
	# script would fall straight into its own EXIT trap, tearing the stack down a moment
	# after printing this banner. Watch the process instead.
	while kill -0 "$WEB_PID" 2>/dev/null; do sleep 1; done
	exit 0
fi

# An array, not "${@:-token builder}": quoted, that default is one word, so a no-argument
# run silently tested a single mode called "token builder" and skipped token entirely.
MODES=("$@")
[ "${#MODES[@]}" -eq 0 ] && MODES=(token builder)
start_pages
for mode in "${MODES[@]}"; do
	run_mode "$mode"
done

echo
echo "passed: ${PASS_TOTAL}   failed: ${FAIL_TOTAL}"
[ "$FAIL_TOTAL" -eq 0 ]
