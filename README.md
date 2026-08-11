# cf-termbin

A hardened command-line paste bin on Cloudflare Workers plus D1. Clients `curl` text in,
get a short URL back, and it expires on its own after a few days.

It exists because the service it replaces (fiche on a raw TCP port) was found storing
other people's command-and-control material. So a submission has to identify itself, and
it has to read like log output rather than a payload wearing a log's envelope. thingino
runs it for diagnostic reports, but nothing here is specific to that beyond the defaults;
see [Run your own](#run-your-own).

## Layout

```
src/index.js       routes, submit and view pipelines, cron reclaimer
src/envelope.js    the format gate and the payload shape scanner
src/auth.js        admin auth: builder session, shared key, or disabled
src/budget.js      Durable Object, per-kind daily report and byte counters
src/slug.js        slug and token generation
src/crypto.js      sha256hex and a constant-time compare, shared by both callers
src/respond.js     inert response headers
web/               the admin portal: static site, published to Pages
tools/vendor.sh    copies shared web assets out of thingino-image-builder
tests/unit.mjs     gate, metadata extraction, shape scanner (fast, no wrangler)
tests/smoke.sh     end-to-end against wrangler dev
tests/web.sh       the admin page in a real browser; --serve leaves the stack up
.github/workflows/pages.yml   publishes web/ and points it at the Worker
```

## Requirements

Node 22 or newer, which is what current wrangler needs. If your system Node is
older, put a newer one ahead of it on `PATH` for the session.

Shell examples below use `$BIN` for the bin's base URL, so set it once:

```sh
BIN=https://<your-worker>.workers.dev
```

## Run it locally

```sh
tests/web.sh --serve          # or: tests/web.sh --serve token
```

That starts a plain static server standing in for GitHub Pages, a `wrangler dev` pointed
at it through `PORTAL_UPSTREAM`, seeds an admin session, prints the URL and leaves it up.
The portal is then at `/admin/` on the Worker, which is exactly where it sits in
production, so the shipped CSP applies unmodified and there is nothing local-only in the
path being tested.

It is a mode of the browser suite rather than its own script on purpose: the awkward
parts, waiting for storage to come up and walking the process tree on teardown, have one
implementation instead of two that drift.

## Test

```sh
node tests/unit.mjs   # 111 checks, ~instant
tests/smoke.sh        # 270 checks over 13 wrangler dev instances
tests/web.sh          # 21 checks in Chromium, both auth modes
```

The smoke suite covers every route, both gates, the D1 blob round trip at a realistic
430 KiB, the cron reclaimer, both budget limits, all three auth modes, and the strict
envelope mode. No Cloudflare account needed; it runs against miniflare.

Both suites carry the cases that real hardware and a 599 MiB false-positive sweep turned
up, in both directions: a payload chunked below the old run threshold and an ELF hidden by
a one-byte prefix must be refused, and a `sha256sum` listing, a degraded device's
five-section report, an IPv6 NFS mount line and a wifi scan full of accented SSIDs must
not be.

`tests/web.sh` drives `web/` in a real browser, against a real Worker, behind the
same-origin proxy so the shipped CSP applies unmodified. It is separate because the
interesting failure there is not a status code but a credential going to the wrong
origin, which no amount of Worker testing can see. Playwright is deliberately not a
dependency, since it pulls a browser download; the suite skips cleanly without it.

It starts and stops its own servers. If it ever leaves strays behind, kill them, because
leaked `workerd` processes hold around 90 MB each and once a few pile up miniflare's
storage services start answering 500 for reasons that look like a bug in the Worker:

```sh
pgrep -f '[w]orkerd-linux-64' | xargs -r kill -9
```

## Deploy

```sh
wrangler deploy
```

`wrangler login`, or a `CLOUDFLARE_API_TOKEN` in the environment, whichever you already use.
The token needs Workers Scripts:Edit and D1:Edit on the account, and nothing else.

The thingino deployment needs no admin secret: auth is delegated to
thingino-image-builder, so an account enrolled there, with its TOTP, is an account here,
and disabling it there revokes access here on the next request. See `src/auth.js` for why
login is delegated rather than reimplemented, and [Run your own](#run-your-own) for the
modes that need no builder at all.

The portal deploys separately: pushing anything under `web/` triggers
`.github/workflows/pages.yml`, which stamps the version and short sha into `config.js` and
publishes to GitHub Pages. The Worker then **serves that site at `/admin/` on its own
origin**, fetching it from `PORTAL_UPSTREAM`.

That indirection buys the thing worth having, which is one origin: the page's API calls
are same-origin, so the Worker grants no CORS at all (`ALLOW_ORIGIN` is empty) and the
page's CSP needs no wildcard for a cross-origin API. It also keeps what moving the portal
out was for, since the assets are not embedded: the script stays small and the portal
deploys without `wrangler deploy`.

Two consequences to know. `PORTAL_UPSTREAM` must match the repository name, because that
is the path a GitHub Pages project site is served under. And `/admin` redirects to
`/admin/`: without the trailing slash every relative asset resolves against `/` and 404s.

`vendor/` is shared with thingino-image-builder verbatim (refresh with
`tools/vendor.sh`) rather than being a copy that drifts.

The schema is created on first use, so there is no migration step and no first-run
setup beyond the bindings in `wrangler.toml`. The cron trigger there handles
expired-row reclamation.

## Use

Every submission must present `X-Thingino-Client` matching `CLIENT_ID`. On a thingino
device that is the `CPE_NAME` already in `/etc/os-release`:

```sh
# submit a file
CPE=$(. /etc/os-release; echo "$CPE_NAME")
curl -H "X-Thingino-Client: $CPE" --data-binary @/tmp/rsd.log $BIN/

# read
curl $BIN/<slug>

# delete early, with the token the submit returned
curl -X DELETE $BIN/<slug> -H 'X-Delete-Token: <token>'

# admin takedown, without the submitter's token
curl -X DELETE $BIN/<slug> -H "Authorization: Bearer $SESSION"
```

`Accept: application/json` on the submit returns `url`, `slug`, `expires`, `ttl_days`,
`kind`, `size` and `delete_token` instead of text.

Anything that can pipe works the same way, since the body is read as it arrives and needs
no `Content-Length`:

```sh
dmesg | curl -H "X-Thingino-Client: $CPE" --data-binary @- $BIN/
```

## Admission

The client id is the only thing that decides whether a submission is accepted. It is
**not a secret** in the thingino deployment: it is in every firmware image, derivable
from the project name, and printed in every report the bin serves. What it buys is that a
scanner spraying an open endpoint gets nowhere, so a payload has to be aimed at this bin
deliberately. The shape gate is what refuses payloads.

The report format decides *treatment*, not admission. A recognised report (a
`===[ THINGINO ]===` block with `ID=thingino`) gets the longer retention and the
section-count check; anything else is stored as a `paste` on a shorter leash: 1 day
instead of 3, with its own smaller daily allowance, so abuse of the permissive path runs
out first and expires fastest. It cannot spend the diag allowance.

`REQUIRE_ENVELOPE=1` changes that: with it, anything that is not a recognised report is
refused outright.

**Refusals say nothing.** Every gate returns the same one-line `not accepted (cf-ray)`,
with the real reason logged against that ray. Naming the check would be a tuning dial, and
telling a caller what to send instead is a written invitation.

## What it refuses

Every submission is measured before it is stored. The checks run in order, the first to fire
wins, and all of them answer the same opaque refusal.

- **Encoded data**, by how much of the body sits in tokens that look encoded. This is the
  primary signal, and it is not a signature: real device output measures under 2.4% and mostly
  exactly zero, while a base64 payload measures a third of the body upwards, depending on how
  finely it is chunked. Base32 and long hex are counted the same way. Hex of exactly a digest
  length is not, so a `sha256sum` listing is ordinary text.
- **Executable and archive headers**, raw and base64: ELF, PE, gzip, zip, and a base64
  `#!/bin/sh`. Each base64 form is matched at all three byte alignments, because one byte in
  front of a payload shifts the encoding and defeats a single literal.
- **Fetch-and-run chains**: a download piped into any interpreter including `| busybox sh`,
  fetch-then-`chmod`-then-run with no pipe at all, `base64 -d | sh`, and a per-architecture
  binary as the last element of a URL.
- **Binary and re-encoded bodies**, by the share of bytes that are text. Valid UTF-8 counts as
  text, so a log in any script passes, while raw binary measures about 45%.
- **A fabricated envelope**: a recognised report has to contain recognised section names, not
  merely enough `===[ x ]===` lines to clear a count.

Calibrated against real reports from three devices, 49 real command outputs and 599 MiB of
real firmware content, with no false positive on any device output. Each threshold carries its
measured value in a comment beside it in `src/envelope.js`.

It is not a virus scanner and does not try to be: it measures shape, not meaning, so it does
not care what the bytes decode to. Anyone who can submit and observe can map the checks by
bisecting accepted against refused.

## What is stored

The report itself, for `TTL_DAYS` (3) or `PASTE_TTL_DAYS` (1), then the cron reclaims it.
Beside it only what is needed to serve and expire it: size, kind and the hash of the delete
token. Nothing is lifted out of the body into a column of its own.

**Nothing can be made permanent.** There is no path that exempts a report from expiry, so
the working set can never exceed the daily byte budget times the retention window, which is
what makes storage provably bounded. If a log needs to outlive its window, download it and
attach it to the issue, where the discussion already lives.

An `events` table records what happened, kept for **7 days** (`ABUSE_TTL_DAYS`) and
separate from the report row on purpose: that window is longer than the retention window,
so a column on `pastes` would be reclaimed with the report at 3 days and never reach a
week. One row per accepted submission, per admin action and per reclaim run:

| kind | written when |
| --- | --- |
| `submit` | a report is accepted, in the same batch that stores it |
| `delete` | one report is deleted, naming the admin or the submitter's token |
| `purge_reports` | every report is deleted at once |
| `purge_events` | the log itself is cleared, logged *after* the deletes so it survives |
| `paused` / `resumed` | the kill switch is used |
| `reap` | the cron expires something, skipped entirely when it finds nothing |

Admin logins are not in that table, because they do not happen here: this Worker never sees a
password or a code. In builder mode the listing reads `admin_login_ok`, `admin_login_fail` and
`admin_login_throttled` out of the builder's own events table, which is already bound for auth,
and merges them in by time. So clearing this log cannot erase the login trail: those rows are
not this Worker's to delete.

Only logins through *this* bin's sign-in page are shown. The builder records which app each
login came through and `LOGIN_APP` selects it here, so a login to the builder that never touched
this bin stays on the builder's page. That label is an audit field the caller supplies: it
decides which rows are displayed and nothing else. It grants no access at either end, and a row
without it is not assumed to be ours.

Only *successful* submissions are recorded. Refused ones stay in the ephemeral log,
because writing a row per refusal would turn a flood into database writes against your
100k/day.

A submitter's address is kept against their submission. An admin action stores who did it
and no address, so the retention promise above stays about submitters. Nothing else is
kept: no ASN, no user agent, no headers. Read the log with an admin credential:

```sh
curl -H "Authorization: Bearer $SESSION" "$BIN/admin/events?ip=203.0.113.7"
curl -H "Authorization: Bearer $SESSION" "$BIN/admin/events?slug=<slug>"
curl -H "Authorization: Bearer $SESSION" "$BIN/admin/events?limit=20"
```

## Configuration

`[vars]` in `wrangler.toml`:

| Var | Default | Meaning |
|---|---|---|
| `CLIENT_ID` | `cpe:/o:thinginoproject:thingino` | required `X-Thingino-Client` prefix |
| `REQUIRE_ENVELOPE` | `0` | `1` refuses anything that is not a recognised report |
| `AUTH_MODE` | inferred | `builder`, `token` or `none` |
| `PORTAL_UPSTREAM` | the Pages site | where the admin portal is published; the Worker serves it at `/admin/`. Empty means no portal |
| `ALLOW_ORIGIN` | `""` | empty because the portal is same-origin. Set an exact origin only if you host it elsewhere; never a wildcard |
| `SLUG_LEN` | `8` | slug characters; validation accepts 4-26 so changing it never 404s old links |
| `MAX_BYTES` | `524288` | 512 KiB; the largest real report is 410 KB, and this bounds the shape scan inside the 10 ms CPU budget |
| `TTL_DAYS` | `3` | retention for recognised reports, clamped by `MAX_TTL_DAYS` |
| `MAX_TTL_DAYS` | `3` | ceiling on the above |
| `PASTE_TTL_DAYS` | `1` | retention for anything else; shorter on purpose |
| `DAILY_MAX` | `2000` | reports per day, secondary guard |
| `DAILY_MAX_BYTES` | `104857600` | bytes per day; this is what bounds the database |
| `PASTE_DAILY_MAX` | `200` | separate, smaller allowance for non-report submissions |
| `PASTE_DAILY_MAX_BYTES` | `20971520` | 20 MB/day for the same |
| `SHAPE_BLOB_PCT` | `10` | reject if more of the body than this sits in encoded-looking tokens |
| `SHAPE_MIN_SECTIONS` | `3` | floor against a bare wrapper; real reports run 5 to 30 |
| `SHAPE_MIN_KNOWN_SECTIONS` | `2` | recognised section names required, which is the check that means something |
| `BLOCK_DROPPERS` | `1` | `0` disables the fetch-and-run checks if one ever false-fires |
| `ABUSE_TTL_DAYS` | `7` | how long an event row, and so a submitter address, is kept |
| `RECLAIM_BATCH` | `50` | expired rows deleted per cron tick |
| `PUBLIC_BASE` | `""` | base URL in responses; empty derives from the request |

Secrets, not vars: `ADMIN_KEY`, only in `token` auth mode.

The portal has its own config in `web/config.js` (`API_BASE`, `AUTH_ORIGIN`,
`APP_VERSION`, `GIT_SHA`), which the Pages workflow rewrites at deploy time. `API_BASE` is
empty in both, since the API is same-origin; `AUTH_ORIGIN` is the one genuinely
cross-origin dependency and is named exactly in the page's CSP.

The remaining thresholds are code-only, in `src/envelope.js`: the longest unbroken token
(1024; real reports measure 138 to 190), the longest run of encoded lines (8; real reports
measure 0), the floor on absolute encoded bytes below which the ratio is not consulted
(1024, so one ssh key in a small config is not a payload), and the share of non-ASCII bytes
(95%, set by real CJK text rather than by the attack). They are backstops for a payload
small enough to hide inside the ratio, and each is individually evadable by another's
encoding, which is why all of them exist.

The ratio itself counts **tokens**, not runs of base64 characters, and that distinction is
the whole check: run length is the one thing an attacker sets for free. Every threshold
carries its measured value in a comment next to it in `src/envelope.js`, so the headroom is
auditable without leaving the code.

## Run your own

The admin portal is optional, because a self-hoster has no image builder to log in
against.

```sh
git clone <this repo> && cd cf-termbin && npm install
wrangler d1 create my-bin                 # put the id in wrangler.toml
# in wrangler.toml: set CLIENT_ID to a random string your clients will send,
#                   and remove the AUTHDB binding (that is thingino's builder)
wrangler secret put ADMIN_KEY             # or skip it, and admin is simply off
wrangler deploy
```

Then send something:

```sh
echo hello | curl -H "X-Thingino-Client: <your CLIENT_ID>" --data-binary @- $BIN/
```

**Auth modes**, inferred so you need not set `AUTH_MODE` at all:

| mode | when | what you get |
|---|---|---|
| `builder` | an `AUTHDB` binding is present | accounts in thingino-image-builder, with TOTP |
| `token` | an `ADMIN_KEY` secret is set | one shared key; the portal asks for it |
| `none` | neither | no admin at all |

`none` is a real option, not a broken state: reports still arrive, serve and expire, and
whoever uploaded one can still delete it with the token they were given. Only the portal
and admin takedown are unavailable, and you need not deploy `web/` at all.

The portal reads `GET /admin/mode`, which is public and reveals only which mode is in use,
so a static page draws the right login form without config duplicated in two places.

**What stays on in every mode**, because it is the reason to use this rather than fiche:
the shape gate, retention and expiry, the daily byte budget, slug entropy, opaque
refusals, and `noindex`. A deployment that switches those off has rebuilt the thing that
got abused.

Unlike thingino's, your `CLIENT_ID` need not be public. A random string you do not
publish is a much stronger filter than a value shipped in open-source firmware.
