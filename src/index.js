import { DailyBudget } from './budget.js';
import { newSlug, newToken, isSlug } from './slug.js';
import { sha256hex, constantTimeEqual } from './crypto.js';
import { parseEnvelope, scanShape, SHAPE_DEFAULTS } from './envelope.js';
import { textResponse, jsonResponse, pasteResponse, notFound } from './respond.js';
import { adminIdentity, authMode } from './auth.js';

export { DailyBudget };

// `Number(null)` is 0, and 0 is finite, so a missing value has to be rejected before
// the finite check rather than after it. Missing it meant `num(searchParams.get('limit'))`
// returned 0 for an absent parameter instead of the default, and every admin query
// without an explicit ?limit answered LIMIT 0, so it returned nothing at all. Env vars
// were unaffected, because an unset binding is undefined and Number(undefined) is NaN.
const num = (v, fallback) => {
	if (v === null || v === undefined || v === '') return fallback;
	const n = Number(v);
	return Number.isFinite(n) ? n : fallback;
};

// Clamped at both ends. SQLite reads a negative LIMIT as no limit, so an upper bound
// alone let ?limit=-1 return the whole table past the 500 cap.
const limitParam = (url, fallback = 50, max = 500) =>
	Math.max(1, Math.min(Math.trunc(num(url.searchParams.get('limit'), fallback)), max));

// Created on first use rather than as a deploy step, so there is no migration to
// forget. One query on a cold isolate, against a 50-query-per-invocation budget.
let schemaReady = null;

function ensureSchema(env) {
	if (!schemaReady) {
		schemaReady = (async () => {
			await env.DB.batch([
				env.DB.prepare(`CREATE TABLE IF NOT EXISTS pastes (
					slug     TEXT PRIMARY KEY,
					created  INTEGER NOT NULL,
					exp      INTEGER NOT NULL,
					size     INTEGER NOT NULL,
					tok      TEXT NOT NULL,
					kind     TEXT,
					body     BLOB NOT NULL
				)`),
				env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_pastes_exp ON pastes(exp)'),
				// Deliberately a separate table. The abuse window is longer than the
				// retention window, so a column on `pastes` would be reclaimed with the
				// report at 3 days and never reach a week.
				env.DB.prepare(`CREATE TABLE IF NOT EXISTS submissions (
					slug    TEXT PRIMARY KEY,
					ip      TEXT NOT NULL,
					kind    TEXT,
					created INTEGER NOT NULL,
					exp     INTEGER NOT NULL
				)`),
				env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_submissions_exp ON submissions(exp)'),
				env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_submissions_ip ON submissions(ip)'),
			]);

			// CREATE TABLE IF NOT EXISTS will not alter a table an earlier version
			// already made, so new columns are added separately and idempotently.
			// Kept out of the batch above because one failing statement fails the lot.
			for (const sql of [
				'ALTER TABLE pastes ADD COLUMN kind TEXT',
				// Dropped rather than left to age out: they held hardware and build identity for
				// every report, which is a device inventory a paste bin has no business keeping.
				// A failure here just means the table never had them.
				'ALTER TABLE pastes DROP COLUMN soc',
				'ALTER TABLE pastes DROP COLUMN build',
				'ALTER TABLE pastes DROP COLUMN model',
				// Held the censor ruleset a report declared. Nothing ever declared one.
				'ALTER TABLE pastes DROP COLUMN redacted',
				// Added after the fact, so existing rows read null and the portal shows no flag
				// for them rather than a wrong one.
				'ALTER TABLE submissions ADD COLUMN country TEXT',
			]) {
				try {
					await env.DB.prepare(sql).run();
				} catch (err) {
					if (!/duplicate column|no such column/i.test(String(err))) throw err;
				}
			}
		})().catch((err) => {
			schemaReady = null; // let the next request retry rather than wedging the isolate
			throw err;
		});
	}
	return schemaReady;
}

export default {
	async fetch(request, env) {
		const url = new URL(request.url);
		const segments = url.pathname.split('/').filter(Boolean);

		// CORS exists only for a portal hosted on some other origin. The portal this ships
		// with is served from /admin/ on this same origin, so it needs none, and ALLOW_ORIGIN
		// is empty by default: no preflight is answered and no CORS header is emitted.
		if (request.method === 'OPTIONS') {
			if (!env.ALLOW_ORIGIN) return notFound();
			const corsable = segments[0] === 'admin' || (segments.length === 1 && isSlug(segments[0]));
			return corsable ? new Response(null, { status: 204, headers: cors(env) }) : notFound();
		}

		// Public on purpose: the portal is a static file that cannot read Worker config, and
		// it needs to know which login form to draw. It reveals which auth mode is in use
		// and nothing else, no credential and no identity.
		if (url.pathname === '/admin/mode' && request.method === 'GET') {
			return withCors(jsonResponse(200, { auth_mode: authMode(env) }), env);
		}

		if (url.pathname === '/robots.txt') {
			return textResponse(200, 'User-agent: *\nDisallow: /\n');
		}

		if (segments.length === 0) {
			if (request.method === 'POST') return submit(request, env, url);
			// Nothing at the root. The usage text it used to serve told a scanner what
			// this is and how to talk to it, which undoes the opaque refusals; a 404 is
			// indistinguishable from any unknown path.
			return notFound();
		}

		const [slug] = segments;

		// The admin API. These are matched BEFORE the portal proxy below, or the proxy would
		// shadow them and fetch `stats` from the static site instead of running the query.
		// ADMIN_API is the guard against that: a new endpoint added here has to be named
		// there too, and the smoke suite checks one of each so the trap cannot go unnoticed.
		// 'admin' contains an 'i', which is not in the slug alphabet, so none of this can
		// collide with a report path.
		if (segments[0] === 'admin' && segments.length === 2 && ADMIN_API.has(segments[1]) && request.method === 'GET') {
			if (segments[1] === 'abuse') return withCors(await abuse(request, env, url), env);
			if (segments[1] === 'stats') return withCors(await stats(request, env), env);
			if (segments[1] === 'reports') return withCors(await reports(request, env, url), env);
		}

		// Purging everything, which is a takedown tool rather than routine: reports expire on
		// their own at TTL_DAYS and submission records at ABUSE_TTL_DAYS.
		if (
			segments[0] === 'admin' &&
			segments.length === 2 &&
			request.method === 'DELETE' &&
			(segments[1] === 'reports' || segments[1] === 'abuse')
		) {
			return withCors(await purge(request, env, url, segments[1]), env);
		}

		if (segments[0] === 'admin' && segments.length === 2 && segments[1] === 'pause' && request.method === 'POST') {
			return withCors(await pause(request, env, url), env);
		}

		// Everything else under /admin is the portal itself, proxied from wherever it is
		// published. Serving it from this origin is not cosmetic: it makes the page and the
		// API same-origin, so the page needs no CORS grant from the Worker and its CSP needs
		// no wildcard for a cross-origin API.
		if (url.pathname === '/admin') {
			// Load-bearing. Without the trailing slash every relative asset in the page
			// resolves against / instead of /admin/, and all of them 404.
			return Response.redirect(`${baseUrl(env, url)}/admin/`, 301);
		}
		if (url.pathname.startsWith('/admin/')) return portal(request, env, url);

		if (segments.length === 1) {
			if (request.method === 'GET' || request.method === 'HEAD') return view(request, env, slug);
			if (request.method === 'DELETE') return withCors(await remove(request, env, slug), env);
			return textResponse(405, 'method not allowed\n');
		}


		return notFound();
	},

	// D1 has no per-row expiry, so reclamation is a cron rather than a lifecycle rule.
	// Read-time expiry is already authoritative, so this only frees storage and can lag
	// safely.
	//
	// Everything expires. There used to be an `exp != 0` clause here exempting
	// promoted reports, which made storage growth unbounded and dependent on someone
	// noticing. Now the working set is provably bounded by the daily byte budget
	// times the retention window, with nothing to watch.
	// Bounded per tick: a DELETE of many ~430 KiB rows would otherwise risk the
	// 30 second query ceiling.
	async scheduled(event, env) {
		await ensureSchema(env);
		const now = Math.floor(Date.now() / 1000);
		const batch = num(env.RECLAIM_BATCH, 50);

		const reports = await env.DB.prepare(
			'DELETE FROM pastes WHERE slug IN (SELECT slug FROM pastes WHERE exp < ? LIMIT ?)',
		)
			.bind(now, batch)
			.run();

		// Its own cutoff, so abuse records outlive the reports they point at.
		const records = await env.DB.prepare(
			'DELETE FROM submissions WHERE slug IN (SELECT slug FROM submissions WHERE exp < ? LIMIT ?)',
		)
			.bind(now, batch)
			.run();

		console.log(
			`reclaim: ${reports.meta?.changes ?? 0} report(s), ${records.meta?.changes ?? 0} abuse record(s), db size now ${records.meta?.size_after ?? '?'} bytes`,
		);
	},
};

// The kill switch. Refuses submissions while leaving reads, deletes and expiry alone, which
// is what an incident wants: stop taking new material without hiding what is already stored.
async function pause(request, env, url) {
	if (!(await adminIdentity(request, env))) return notFound();
	const state = url.searchParams.get('state');
	if (state !== 'on' && state !== 'off') return textResponse(400, 'state must be on or off\n');
	const budget = env.BUDGET.get(env.BUDGET.idFromName('global'));
	const result = await budget.setPaused(state === 'on');
	console.log(`submissions ${result.paused ? 'paused' : 'resumed'}`);
	return jsonResponse(200, result);
}

// Deletes every row from one table, in bounded batches for the same reason the cron does:
// a single unbounded DELETE over a few hundred rows of ~430 KiB each risks D1's 30 second
// query ceiling, and D1 allows 50 queries per invocation. So a call clears up to
// PURGE_BATCHES x RECLAIM_BATCH rows and reports what is left, and the caller repeats if it
// has to. That is honest about a partial result rather than appearing to finish.
const PURGE_BATCHES = 20;

async function purge(request, env, url, what) {
	// Auth first, so an unauthenticated caller sees the same 404 as any unknown path and
	// cannot tell this endpoint exists.
	if (!(await adminIdentity(request, env))) return notFound();
	// Only after that is a clear error safe: the caller is already known to be an admin.
	if (url.searchParams.get('confirm') !== 'all') {
		return textResponse(400, 'add ?confirm=all to purge everything\n');
	}
	await ensureSchema(env);

	// Both tables key on slug, so one statement shape covers either. `table` is chosen from a
	// two-way comparison rather than interpolated from the request, so nothing user-supplied
	// reaches the SQL.
	const table = what === 'reports' ? 'pastes' : 'submissions';
	const batch = num(env.RECLAIM_BATCH, 50);

	let deleted = 0;
	for (let i = 0; i < PURGE_BATCHES; i++) {
		const run = await env.DB.prepare(
			`DELETE FROM ${table} WHERE slug IN (SELECT slug FROM ${table} LIMIT ?)`,
		)
			.bind(batch)
			.run();
		const n = run.meta?.changes ?? 0;
		deleted += n;
		if (n < batch) break;
	}

	const left = await env.DB.prepare(`SELECT COUNT(*) n FROM ${table}`).first();
	const remaining = left?.n ?? 0;
	console.log(`purge ${what}: deleted ${deleted}, ${remaining} remaining`);
	return jsonResponse(200, { purged: what, deleted, remaining });
}

// Endpoint names under /admin that belong to the API rather than to the static portal.
const ADMIN_API = new Set(['mode', 'stats', 'reports', 'abuse']);

// Serves the portal from this origin by fetching it from wherever it is published, which
// for this deployment is GitHub Pages. The assets are not embedded in the Worker: the
// script stays small and the portal still deploys on its own, which was the point of
// moving it out, while the browser sees one origin.
//
// PORTAL_UPSTREAM empty means no portal, which is the honest state for a deployment that
// never published one. It 404s rather than pretending.
async function portal(request, env, url) {
	const upstream = (env.PORTAL_UPSTREAM || '').replace(/\/+$/, '');
	if (!upstream) return notFound();
	// 404, not 405. Everything under /admin answers 404 when it is not a legitimate GET, so
	// that a probe cannot tell an endpoint that exists from one that does not.
	if (request.method !== 'GET' && request.method !== 'HEAD') return notFound();

	// `|| 'index.html'` is what makes /admin/ resolve to the page. Path traversal cannot
	// escape the upstream prefix because URL normalises `..` before we read the pathname.
	const rest = new URL(url.pathname, 'http://x').pathname.slice('/admin/'.length) || 'index.html';

	// Only genuinely content-stable files may be cached. The portal's own files carry no
	// fingerprint in their names, so caching them serves a fresh page shell alongside stale
	// scripts, which is exactly what happened: a deploy landed new markup while admin.js was
	// still the previous build for ten minutes, and the new controls did nothing.
	const immutable = rest.startsWith('vendor/') || rest.startsWith('favicon.');

	const fetched = await fetch(`${upstream}/${rest}`, {
		method: request.method,
		headers: { accept: request.headers.get('accept') || '*/*' },
		redirect: 'follow',
		// The response header below governs the browser; this governs Cloudflare's own cache of
		// the subrequest, which would otherwise keep serving the upstream's max-age for a
		// mutable file and hide a deploy just as effectively.
		cf: immutable ? undefined : { cacheTtl: 0 },
	});

	// Pass the upstream body and content type through, but not its caching or security
	// headers: this origin decides those, and a static host's defaults are not ours.
	const headers = new Headers();
	for (const h of ['content-type', 'content-length', 'etag', 'last-modified']) {
		const v = fetched.headers.get(h);
		if (v) headers.set(h, v);
	}
	headers.set('x-content-type-options', 'nosniff');
	headers.set('referrer-policy', 'no-referrer');
	headers.set('x-robots-tag', 'noindex, nofollow');
	headers.set('cache-control', immutable ? 'public, max-age=86400' : 'no-store');
	return new Response(fetched.body, { status: fetched.status, headers });
}

// One opaque refusal for every gate.
//
// The reason never reaches the client. Telling someone "send X-Thingino-Client" is
// a written invitation, and naming the check that caught them is a tuning dial.
// Neither stops a determined attacker, who learns the same thing by bisecting
// accepted against refused, but both remove the casual case: read the error, do
// what it says, succeed.
//
// Operational limits stay informative, because knowing the size cap does not help
// anyone bypass anything, and a truncated report is a real problem a user can fix.
//
// The cf-ray goes in the body so a refused user can quote something a maintainer can
// find in `wrangler tail`, which logs the real reason against the same ray.
// Mirrors the builder's cors() helper. Authorization rather than cookies, so a
// wildcard origin grants nothing on its own: every one of these endpoints still needs a
// valid builder session.
function cors(env) {
	return {
		'access-control-allow-origin': env.ALLOW_ORIGIN,
		'access-control-allow-methods': 'GET,DELETE,OPTIONS',
		'access-control-allow-headers': 'authorization,content-type',
		vary: 'Origin',
	};
}

function withCors(response, env) {
	if (!env.ALLOW_ORIGIN) return response;
	const headers = new Headers(response.headers);
	for (const [k, v] of Object.entries(cors(env))) headers.set(k, v);
	return new Response(response.body, { status: response.status, headers });
}

function refuse(request, reason, detail = '') {
	const ray = request.headers.get('cf-ray') || 'local';
	console.log(`refused ${reason} ray=${ray}${detail ? ' ' + detail : ''}`);
	// One line, nothing else. The prose that used to follow was itself a hint about
	// what the bin expects, and the ray is all a legitimate user needs to quote.
	return textResponse(422, `not accepted (${ray})\n`);
}

// Size limits stay informative, unlike the gate refusals: knowing the cap helps
// nobody bypass anything, and a report too big to upload is a real problem a user
// can act on by trimming it on the device.
function oversized(maxBytes) {
	return textResponse(
		413,
		`report over ${maxBytes} bytes\n\n` +
			'Trim it on the device instead of relying on this rejection: a truncated log\n' +
			'with a marker line is still triageable, a 413 is not.\n',
	);
}

function baseUrl(env, url) {
	return (env.PUBLIC_BASE || url.origin).replace(/\/+$/, '');
}

// The body arrives chunked with no Content-Length whenever the diag script pipes
// into curl, so the cap has to be enforced while reading rather than read off a
// header.
//
// On overflow we stop keeping the bytes but keep reading to the end of the stream
// before answering 413. Both shortcuts are worse, and both were measured:
// cancelling the body mid-upload crashes the workers runtime, and abandoning it
// unread takes the runtime down too. Draining costs nothing in memory because we
// drop every chunk once over the limit, it costs no CPU because awaiting I/O does
// not count against the budget, and its worst case is bounded by the platform's
// own request body limit rather than by anything we would enforce here.
async function readLimited(request, max) {
	if (!request.body) return new Uint8Array(0);

	const reader = request.body.getReader();
	const chunks = [];
	let total = 0;
	let over = false;

	for (;;) {
		const { done, value } = await reader.read();
		if (done) break;

		total += value.byteLength;
		if (total > max) {
			over = true;
			chunks.length = 0;
			continue;
		}
		if (!over) chunks.push(value);
	}

	if (over) return null;

	const out = new Uint8Array(total);
	let offset = 0;
	for (const chunk of chunks) {
		out.set(chunk, offset);
		offset += chunk.byteLength;
	}
	return out;
}

async function submit(request, env, url) {
	// Matches wrangler.toml. A fallback larger than the configured value meant a
	// deployment that dropped the var silently accepted bodies past the size the shape
	// scan was measured against inside the 10 ms CPU budget.
	const maxBytes = num(env.MAX_BYTES, 524288);

	// If the client declared a length, believe it and refuse before reading a byte.
	// Only an optimisation, not a guarantee: a chunked upload has no Content-Length
	// and still has to be drained. But `--data-binary @file` always sends one, so
	// the honest oversized case costs nothing and only a deliberate one pays.
	const declared = Number(request.headers.get('content-length') || 0);
	if (declared > maxBytes) return oversized(maxBytes);

	const bytes = await readLimited(request, maxBytes);
	if (bytes === null) return oversized(maxBytes);
	if (bytes.byteLength === 0) return textResponse(400, 'empty body\n');

	// Logs routinely carry bytes that are not valid UTF-8 (dmesg ring, binary
	// junk), so scan a lossy decode.
	const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes);

	// The client id is required for everything, diag reports included. Nothing is
	// accepted from a caller that has not identified itself as a thingino device, so
	// a scanner spraying an open endpoint gets nowhere at all.
	//
	// It is not a secret and is not treated as one: it ships in every image and is
	// printed in every report the bin serves. The shape gate is what refuses
	// payloads. This just means a payload has to be aimed at us deliberately.
	if (!isClient(request, env)) return refuse(request, 'no client id');

	// The envelope no longer decides admission, only how the report is treated: a
	// recognised diag report gets the longer retention and the section-count check.
	const envelope = parseEnvelope(text);

	// REQUIRE_ENVELOPE is the strict setting, off by default because it is stricter than
	// anything shipped so far: today the client id admits any text, and the envelope only
	// decides whether a submission gets the longer diag retention. Turning it on refuses
	// anything that is not a recognised report.
	if (env.REQUIRE_ENVELOPE === '1' && !envelope.ok) return refuse(request, 'envelope required');

	const kind = envelope.ok ? 'diag' : 'paste';

	// Gate 2: shape. Does this read like a log, or like a payload wearing a log's
	// envelope? Secrets are the diag script's problem; this is the bin defending
	// itself as a public write endpoint. See src/envelope.js for the measurements
	// behind each threshold.
	const shape = scanShape(bytes, text, {
		blobPercent: num(env.SHAPE_BLOB_PCT, SHAPE_DEFAULTS.blobPercent),
		// Arbitrary command output has no ===[ ]=== structure, so both section checks
		// only mean something for a diag report.
		minSections: kind === 'diag' ? num(env.SHAPE_MIN_SECTIONS, SHAPE_DEFAULTS.minSections) : 0,
		minKnownSections: kind === 'diag' ? num(env.SHAPE_MIN_KNOWN_SECTIONS, SHAPE_DEFAULTS.minKnownSections) : 0,
		blockDroppers: env.BLOCK_DROPPERS !== '0',
	});

	if (shape.failed) {
		return refuse(
			request,
			shape.failed,
			JSON.stringify({
				...shape.metrics,
				blobPercent: +shape.metrics.blobPercent.toFixed(2),
				printablePercent: +shape.metrics.printablePercent.toFixed(3),
			}),
		);
	}

	// Separate allowances per door. The permissive one gets the smaller leash: it is
	// a convenience, so abuse of it should run out first and expire fastest.
	const day = new Date().toISOString().slice(0, 10);
	const budget = env.BUDGET.get(env.BUDGET.idFromName('global'));
	const dayCount = kind === 'diag' ? num(env.DAILY_MAX, 2000) : num(env.PASTE_DAILY_MAX, 200);
	const dayBytes = kind === 'diag' ? num(env.DAILY_MAX_BYTES, 104857600) : num(env.PASTE_DAILY_MAX_BYTES, 20971520);
	const allowed = await budget.take(day, kind, dayCount, dayBytes, bytes.byteLength);
	if (!allowed.ok) {
		// Paused is an operator decision, not a limit, so it says so rather than telling a
		// submitter to wait for a reset that will not change anything.
		if (allowed.reason === 'paused') {
			return textResponse(503, 'this bin is not accepting submissions at the moment\n');
		}
		return textResponse(
			503,
			`daily submission budget exhausted (${allowed.reason}), try again after 00:00 UTC\n`,
		);
	}

	const ttlDays =
		kind === 'diag'
			? Math.min(num(env.TTL_DAYS, 3), num(env.MAX_TTL_DAYS, 3))
			: Math.min(num(env.PASTE_TTL_DAYS, 1), num(env.MAX_TTL_DAYS, 3));
	const now = Math.floor(Date.now() / 1000);
	const exp = now + ttlDays * 86400;
	const token = newToken();
	const tokenHash = await sha256hex(token);

	await ensureSchema(env);

	const slug = await insert(env, {
		created: now,
		exp,
		size: bytes.byteLength,
		tok: tokenHash,
		kind,
		body: bytes,
		// Kept for abuse follow-up only, on its own week-long clock. Written in the
		// same batch as the report so a submission can never be recorded without its
		// report, or the other way round.
		ip: request.headers.get('cf-connecting-ip') || '',
		// The two-letter origin, which the edge supplies for nothing. It is strictly less
		// information than the address already stored beside it, and it makes an abuse listing
		// readable at a glance instead of a column of numbers. Absent in local dev, so null.
		country: request.cf?.country || null,
		abuseExp: now + num(env.ABUSE_TTL_DAYS, 7) * 86400,
	}, env.SLUG_LEN);
	if (slug === null) return textResponse(500, 'could not store the report\n');

	// Analytics, if a dataset is ever bound. Size and shape only: the point of dropping the
	// hardware columns would be lost if the same values went to an analytics index instead.
	if (env.AE) {
		env.AE.writeDataPoint({
			blobs: [kind],
			doubles: [bytes.byteLength, shape.metrics.blobPercent],
			indexes: [kind],
		});
	}

	const base = baseUrl(env, url);
	const link = `${base}/${slug}`;
	const expiresAt = new Date(exp * 1000).toISOString();

	if ((request.headers.get('accept') || '').includes('application/json')) {
		return jsonResponse(201, {
			url: link,
			slug,
			expires: expiresAt,
			ttl_days: ttlDays,
			kind,
			delete_token: token,
			size: bytes.byteLength,
		});
	}

	const lines = [
		link,
		'',
		`expires: ${expiresAt} (${ttlDays} day${ttlDays === 1 ? '' : 's'})`,
		`delete:  curl -X DELETE ${link} -H 'X-Delete-Token: ${token}'`,
	];
	// Slug URL alone on line 1 so `URL=$(... | head -1)` works in a script.
	return textResponse(201, lines.join('\n') + '\n');
}

// The slug primary key is the uniqueness gate, so a collision surfaces as a
// constraint error rather than needing a conditional write. At 40 bits against the
// few hundred rows live at once that is a ~3e-10 chance per insert; the retry costs
// nothing when it does not fire.
async function insert(env, row, slugLen) {
	const sql = `INSERT INTO pastes
		(slug, created, exp, size, tok, kind, body)
		VALUES (?, ?, ?, ?, ?, ?, ?)`;

	for (let attempt = 0; attempt < 3; attempt++) {
		const slug = newSlug(slugLen);
		try {
			await env.DB.batch([
				env.DB.prepare(sql).bind(
					slug,
					row.created,
					row.exp,
					row.size,
					row.tok,
					row.kind,
					// readLimited and TextEncoder both hand back exactly sized arrays, so
					// the backing buffer is the payload and nothing else.
					row.body.buffer,
				),
				env.DB.prepare(
					'INSERT INTO submissions (slug, ip, kind, country, created, exp) VALUES (?, ?, ?, ?, ?, ?)',
				).bind(slug, row.ip, row.kind, row.country, row.created, row.abuseExp),
			]);
			return slug;
		} catch (err) {
			if (!/UNIQUE|constraint/i.test(String(err))) throw err;
		}
	}
	return null;
}

// A row with a missing or unreadable expiry counts as expired rather than immortal,
// which is the safe direction for the failure.
function expired(row) {
	return Math.floor(Date.now() / 1000) > Number(row.exp || 0);
}

// D1 hands BLOBs back as Array<number>, not ArrayBuffer.
function toBytes(body) {
	if (body === null || body === undefined) return new Uint8Array(0);
	if (body instanceof ArrayBuffer) return new Uint8Array(body);
	if (Array.isArray(body)) return new Uint8Array(body);
	if (typeof body === 'string') return new TextEncoder().encode(body);
	return new Uint8Array(0);
}

async function view(request, env, slug) {
	if (!isSlug(slug)) return notFound();
	await ensureSchema(env);

	const headOnly = request.method === 'HEAD';

	// HEAD does not need the blob, and not reading it keeps a probe from costing
	// the same as a full fetch.
	const row = headOnly
		? await env.DB.prepare('SELECT exp, size FROM pastes WHERE slug = ?').bind(slug).first()
		: await env.DB.prepare('SELECT exp, size, body FROM pastes WHERE slug = ?').bind(slug).first();

	if (!row) return notFound();

	// The cron reclaimer lags by design, so a row can still be present past its
	// cutoff. Expiry is decided here, which makes the window exact. HEAD answers
	// 410 too: a probe should not tell a different story than a read.
	if (expired(row)) {
		return textResponse(
			410,
			headOnly ? null : 'this diag report has expired\n\nAsk the reporter for a fresh one.\n',
		);
	}

	// `size` was selected for the HEAD path and then dropped, so a HEAD answered without
	// a length and told a caller nothing a GET would not. Set it explicitly: with a null
	// body the runtime has nothing to derive it from.
	return pasteResponse(
		headOnly ? null : toBytes(row.body),
		Number(row.exp || 0),
		headOnly ? { 'content-length': String(Number(row.size || 0)) } : {},
	);
}

// Admits a submission at all. thingino sends its CPE_NAME straight out of
// /etc/os-release, e.g. `cpe:/o:thinginoproject:thingino:1`; another deployment sets
// CLIENT_ID to whatever its clients send.
//
// This is not secret and is not treated as one. It is already in every firmware
// image, it is derivable from the project name alone, and it appears verbatim in the
// THINGINO section of every diag report this bin serves publicly. What it buys is
// the thing that actually happened: a port scanner spraying exploit payloads sends
// no such header, so it is filtered for free. Anyone who reads one paste can forge
// it, which is why the shape gate applies to this door too and is the real defence.
//
// Matched as a prefix so a thingino version bump (`:1` is VERSION_ID) does not lock out
// every client. A deployment using a random token is unaffected by that: nobody guesses
// a prefix of one either. No constant-time compare, deliberately, because in thingino's
// case the value is public and pretending otherwise would be theatre; a deployment that
// treats CLIENT_ID as a real secret should know that.
function isClient(request, env) {
	const expected = env.CLIENT_ID || '';
	if (!expected) return false;
	const presented = request.headers.get('x-thingino-client') || '';
	return presented.length > 0 && presented.startsWith(expected);
}

// The point of keeping submitter addresses is being able to answer "who sent this"
// and "what else did they send". Without a way to ask, the data would be collected
// for nothing, which is the exact trap of keeping what you do not need.
async function abuse(request, env, url) {
	if (!(await adminIdentity(request, env))) return notFound();
	await ensureSchema(env);

	const ip = url.searchParams.get('ip');
	const slug = url.searchParams.get('slug');
	const limit = limitParam(url);

	let rows;
	if (ip) {
		rows = await env.DB.prepare(
			'SELECT slug, ip, kind, country, created, exp FROM submissions WHERE ip = ? ORDER BY created DESC LIMIT ?',
		)
			.bind(ip, limit)
			.all();
	} else if (slug) {
		rows = await env.DB.prepare('SELECT slug, ip, kind, country, created, exp FROM submissions WHERE slug = ?')
			.bind(slug)
			.all();
	} else {
		rows = await env.DB.prepare(
			'SELECT slug, ip, kind, country, created, exp FROM submissions ORDER BY created DESC LIMIT ?',
		)
			.bind(limit)
			.all();
	}

	return jsonResponse(200, {
		retention_days: num(env.ABUSE_TTL_DAYS, 7),
		count: rows.results.length,
		submissions: rows.results.map((r) => ({
			slug: r.slug,
			ip: r.ip,
			kind: r.kind,
			country: r.country || null,
			at: new Date(r.created * 1000).toISOString(),
			record_expires: new Date(r.exp * 1000).toISOString(),
		})),
	});
}

async function stats(request, env) {
	if (!(await adminIdentity(request, env))) return notFound();
	await ensureSchema(env);

	const byKind = await env.DB.prepare(
		'SELECT kind, COUNT(*) n, COALESCE(SUM(size), 0) b FROM pastes GROUP BY kind',
	).all();
	const records = await env.DB.prepare('SELECT COUNT(*) n FROM submissions').all();

	// size_after rides along on any query's meta, so live database size is free.
	const dbBytes = records.meta?.size_after ?? 0;
	const budget = await env.BUDGET.get(env.BUDGET.idFromName('global')).peek();

	return jsonResponse(200, {
		reports: {
			total: byKind.results.reduce((a, r) => a + r.n, 0),
			bytes: byKind.results.reduce((a, r) => a + r.b, 0),
			by_kind: byKind.results,
		},
		abuse: { records: records.results[0]?.n ?? 0, retention_days: num(env.ABUSE_TTL_DAYS, 7) },
		database: { bytes: dbBytes, limit: 524288000, percent_of_limit: ((dbBytes / 524288000) * 100).toFixed(2) },
		budget,
	});
}

async function reports(request, env, url) {
	if (!(await adminIdentity(request, env))) return notFound();
	await ensureSchema(env);

	const limit = limitParam(url);
	// Metadata only. The body is never returned here; the page links to the report,
	// which is served as inert plain text.
	const rows = await env.DB.prepare(
		'SELECT slug, kind, size, created, exp FROM pastes ORDER BY created DESC LIMIT ?',
	)
		.bind(limit)
		.all();

	return jsonResponse(200, {
		count: rows.results.length,
		reports: rows.results.map((r) => ({
			slug: r.slug,
			kind: r.kind,
			size: r.size,
			at: new Date(r.created * 1000).toISOString(),
			expires: new Date(r.exp * 1000).toISOString(),
		})),
	});
}

async function remove(request, env, slug) {
	if (!isSlug(slug)) return notFound();
	await ensureSchema(env);

	const row = await env.DB.prepare('SELECT tok FROM pastes WHERE slug = ?').bind(slug).first();
	if (!row) return notFound();

	const presented = request.headers.get('x-delete-token') || '';
	const holder = presented ? constantTimeEqual(await sha256hex(presented), row.tok || '') : false;

	// A wrong token gets the same 404 as a missing slug, so failing to delete never
	// confirms that a report is there.
	if (!holder && !(await adminIdentity(request, env))) return notFound();

	await env.DB.prepare('DELETE FROM pastes WHERE slug = ?').bind(slug).run();
	// Deliberately just this. The storage layer keeps a restorable history, which is
	// a fact for whoever runs the bin and jargon to whoever is reading the reply.
	return textResponse(200, 'deleted\n');
}
