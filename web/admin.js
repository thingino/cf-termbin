// Admin UI for the thingino diagnostics bin.
//
// Static page, Worker as API: the same split the image builder uses, which is why this
// site can share its vendor/ directory verbatim instead of a Worker-side copy that
// drifts. window.API_BASE and window.GIT_SHA come from config.js, rewritten by the
// Pages workflow at deploy time.
//
// One hard rule: this page never renders a report body. The bin stores text supplied by
// anyone who can reach it, and serves it back as text/plain with nosniff and a sandbox
// CSP so a browser treats it as inert. Embedding it here would undo that and hand
// whoever uploaded it script execution in the one context holding a session. The table
// links out instead, and every value from the API is written with textContent.
//
// Credentials never reach the bin. The form posts them to the builder, which owns the
// password hashes, the TOTP seeds and the login throttling, and returns a session the
// bin verifies against the builder's sessions table.

const API = (window.API_BASE || '').replace(/\/+$/, '');
const AUTH = (window.AUTH_ORIGIN || '').replace(/\/+$/, '');
const KEY = 'tb_admin_session';

const $ = (s) => document.querySelector(s);
let key = sessionStorage.getItem(KEY) || '';

const fmtBytes = (n) =>
	n < 1024 ? n + ' B' : n < 1048576 ? (n / 1024).toFixed(1) + ' KiB' : (n / 1048576).toFixed(2) + ' MiB';

// Always 24 hour and zero padded, the same shape the builder's portal uses so the two read
// alike. `hourCycle:'h23'` rather than `hour12:false`: on current ICU both resolve to h23 in
// every locale, but h23 asks for it outright instead of inheriting whatever the locale's
// preferred 24 hour cycle is, and the other one, h24, renders midnight as 24:00:12. Locale
// still decides field order, so a date stays dd/mm in en-GB and mm/dd in en-US.
const HMS = { hourCycle: 'h23', hour: '2-digit', minute: '2-digit', second: '2-digit' };
const YMD = { year: 'numeric', month: '2-digit', day: '2-digit' };

// Every column is a full date and time. An event log spans days, so a clock alone would leave
// a row from Tuesday indistinguishable from one an hour old.
const stamp = (iso) => new Date(iso).toLocaleString([], { ...YMD, ...HMS });

function show(el, msg, warn) {
	el.textContent = msg || '';
	el.style.display = msg ? '' : 'none';
	el.className = 'alert py-2 small ' + (warn ? 'alert-warning' : 'alert-secondary');
}

async function api(path) {
	const r = await fetch(API + path, { headers: { authorization: 'Bearer ' + key } });
	if (r.status === 404) throw new Error('session rejected: sign in again');
	if (!r.ok) throw new Error('HTTP ' + r.status);
	return r.json();
}

// textContent only. Never innerHTML with a value from the API.
//
// `code` rather than a monospace class, because that is what the builder wraps ids and
// addresses in, and its stylesheet gives code darkorange at .85em. Matching the element
// matches the colour, the size and the row height in one go, instead of three guesses.
function cell(tr, text, asCode) {
	const td = document.createElement('td');
	if (asCode) {
		const c = document.createElement('code');
		c.textContent = text;
		td.appendChild(c);
	} else {
		td.textContent = text;
	}
	tr.appendChild(td);
	return td;
}

// Confirmation popover, ported from the builder: a destructive row action asks where the
// pointer already is, instead of a browser dialog at the top of the window. Resolves true only
// if the action button is used; the x, a click outside, Escape and a second popover all
// resolve false. Only one is ever open, and `refresh()` closes it, because redrawing the table
// would otherwise leave it anchored to a row that no longer exists.
let cpop = null;

function closeConfirm(ok) {
	if (!cpop) return;
	const { el, done, off } = cpop;
	cpop = null;
	off();
	el.remove();
	done(ok);
}

function askConfirm(anchor, message, actionLabel) {
	closeConfirm(false);
	return new Promise((done) => {
		const el = document.createElement('div');
		el.className = 'cpop';
		const msg = document.createElement('div');
		msg.className = 'cpop-msg';
		msg.textContent = message; // textContent, never markup, same rule as every table cell
		const row = document.createElement('div');
		row.className = 'cpop-row';
		const go = document.createElement('button');
		go.type = 'button';
		go.className = 'btn btn-sm btn-danger py-0';
		go.textContent = actionLabel;
		row.appendChild(go);
		const x = document.createElement('button');
		x.type = 'button';
		x.className = 'cpop-x';
		x.setAttribute('aria-label', 'cancel');
		x.textContent = '\u00d7';
		el.append(msg, row, x);
		document.body.appendChild(el);

		// Under the anchor, or above it when there is no room below, with the arrow kept on the
		// anchor even after the box has been clamped inside the viewport.
		const place = () => {
			const a = anchor.getBoundingClientRect();
			const b = el.getBoundingClientRect();
			const above = a.bottom + b.height + 10 > innerHeight && a.top - b.height - 10 > 0;
			const cx = a.left + a.width / 2;
			const left = Math.max(6, Math.min(cx - b.width / 2, innerWidth - b.width - 6));
			el.classList.toggle('above', above);
			el.style.left = left + 'px';
			el.style.top = (above ? a.top - b.height - 6 : a.bottom + 6) + 'px';
			el.style.setProperty('--cpop-arrow', Math.max(8, Math.min(cx - left, b.width - 14)) + 'px');
		};
		place();

		const onKey = (e) => {
			if (e.key === 'Escape') {
				e.preventDefault();
				closeConfirm(false);
			}
		};
		const onDoc = (e) => {
			if (!el.contains(e.target)) closeConfirm(false);
		};
		const off = () => {
			removeEventListener('keydown', onKey);
			removeEventListener('scroll', place, true);
			removeEventListener('resize', place);
			removeEventListener('click', onDoc, true);
		};
		cpop = { el, done, off };
		addEventListener('keydown', onKey);
		addEventListener('scroll', place, true);
		addEventListener('resize', place);
		// The click that opened this is still propagating, so let it finish before the
		// outside-click listener starts to matter.
		setTimeout(() => {
			if (cpop && cpop.el === el) addEventListener('click', onDoc, true);
		}, 0);
		go.addEventListener('click', () => closeConfirm(true));
		x.addEventListener('click', () => closeConfirm(false));
		go.focus();
	});
}

// Origin flag for an ISO 3166-1 alpha-2 code, the same two regional-indicator codepoints the
// builder uses, so no image and no request. Anything not two letters renders as the bare code
// rather than a bogus flag.
const flag = (cc) =>
	/^[A-Za-z]{2}$/.test(cc || '')
		? String.fromCodePoint(...[...cc.toUpperCase()].map((c) => c.codePointAt(0) + 127397))
		: cc || '';

// An id or address that is also a link. Same darkorange code treatment, with the underline
// left to hover so a table of them is not a wall of rules.
function codeLink(td, text, href, opts = {}) {
	const a = document.createElement('a');
	// `ipc` is the builder's name for a clickable address, and here it is also what keeps the
	// orange scoped to addresses so report slugs stay recognisably link-coloured.
	//
	// The underline follows the builder rather than being a preference: its in-table links carry
	// no text-decoration-none and so are underlined, and only its footer links suppress it. The
	// address is the exception because the builder's equivalent is not an anchor at all, just a
	// clickable <code>, so an underline there would be ours and not its.
	a.className = opts.ipc ? 'text-decoration-none ipc' : '';
	if (href) {
		a.href = href;
		if (opts.blank) {
			a.target = '_blank';
			a.rel = 'noreferrer';
		}
	} else {
		a.href = '#';
	}
	const c = document.createElement('code');
	c.textContent = text;
	a.appendChild(c);
	td.appendChild(a);
	return a;
}

function statCard(n, l) {
	const col = document.createElement('div');
	col.className = 'col-6 col-md-4 col-lg';
	const card = document.createElement('div');
	card.className = 'card h-100';
	const body = document.createElement('div');
	body.className = 'card-body py-2';
	const a = document.createElement('div');
	a.className = 'statn';
	a.textContent = n;
	const b = document.createElement('div');
	b.className = 'small muted';
	b.textContent = l;
	body.append(a, b);
	card.appendChild(body);
	col.appendChild(card);
	return col;
}

// What the last stats load reported, so a confirm prompt can name a number instead of
// asking about an unspecified "all".
const lastCounts = { reports: 0, events: 0 };

// Mirrors the builder's kill switch: green or red state, and a button whose colour follows
// what it will do rather than what is true now. The state is held here rather than read back
// out of the rendered word, which tied the switch to its own wording.
let killPaused = false;
function renderKill(paused) {
	killPaused = paused;
	const st = $('#kill-state');
	st.textContent = paused ? 'DISABLED' : 'ENABLED';
	st.className = 'fw-bold ' + (paused ? 'text-danger' : 'text-success');
	const b = $('#kill-btn');
	b.textContent = paused ? 'Enable submissions' : 'Disable submissions';
	b.className = 'btn btn-sm ' + (paused ? 'btn-thingino' : 'btn-outline-danger');
	b.disabled = false;
}

async function toggleKill() {
	const paused = killPaused;
	$('#kill-btn').disabled = true;
	try {
		const r = await fetch(`${API}/admin/pause?state=${paused ? 'off' : 'on'}`, {
			method: 'POST',
			headers: { authorization: 'Bearer ' + key },
		});
		if (!r.ok) throw new Error('HTTP ' + r.status);
		renderKill((await r.json()).paused);
	} catch (e) {
		show($('#err'), 'could not change the switch: ' + e.message, true);
		$('#kill-btn').disabled = false;
	}
}

// Retention, one window per kind.
async function loadTtl() {
	const d = await api('/admin/settings');
	for (const [sel, val] of [
		['#ttlDiag', d.ttl_diag],
		['#ttlPaste', d.ttl_paste],
	]) {
		const el = $(sel);
		el.replaceChildren();
		for (const c of d.choices) {
			const o = document.createElement('option');
			o.value = String(c);
			o.textContent = c === 1 ? '1 day' : `${c} days`;
			el.appendChild(o);
		}
		el.value = String(val);
	}
}

async function saveTtl() {
	const msg = $('#ttlMsg');
	msg.textContent = 'saving…';
	msg.className = 'small muted ms-auto';
	try {
		const r = await fetch(API + '/admin/settings', {
			method: 'POST',
			headers: { authorization: 'Bearer ' + key, 'content-type': 'application/json' },
			body: JSON.stringify({ ttl_diag: Number($('#ttlDiag').value), ttl_paste: Number($('#ttlPaste').value) }),
		});
		if (!r.ok) throw new Error((await r.text()).trim() || 'HTTP ' + r.status);
		msg.textContent = 'saved';
		msg.className = 'small text-success ms-auto';
		await loadTtl();
	} catch (e) {
		msg.textContent = e.message;
		msg.className = 'small text-danger ms-auto';
	}
}

async function loadStats() {
	const s = await api('/admin/stats');
	lastCounts.reports = s.reports.total;
	lastCounts.events = s.events.records;
	renderKill(Boolean(s.budget.paused));
	const c = $('#stats');
	c.replaceChildren(
		statCard(s.reports.total, 'reports stored'),
		statCard(fmtBytes(s.reports.bytes), 'report bytes'),
		statCard(fmtBytes(s.database.bytes), 'database size'),
		statCard(s.database.percent_of_limit + '%', 'of 500 MiB'),
		statCard(s.events.records, 'events logged'),
	);
	const b = $('#budget');
	b.replaceChildren();
	const k = s.budget.kinds || {};
	for (const name of ['diag', 'paste']) {
		const v = k[name] || { n: 0, bytes: 0 };
		b.append(statCard(v.n + ' / ' + fmtBytes(v.bytes), name + ' today'));
	}
}

// Each table shows a short page by default with the builder's expand link under it. Session
// only, exactly as there: a reload returns to the short page rather than re-fetching hundreds
// of rows on every poll.
const PAGE = { reports: 25, events: 60 };
// The Worker clamps ?limit to this, so "show all" cannot mean more than it and the line stays
// honest about that: past it, expanding reads "the latest 500 of 627".
const MAX_PAGE = 500;
const showAll = { reports: false, events: false };
const pageLimit = (which) => (showAll[which] ? MAX_PAGE : PAGE[which]);

// "showing the latest 25 of 144 kept (3 days)", plus the toggle when there is more to see.
function moreLine(el, which, shown, total, kept) {
	el.replaceChildren();
	el.appendChild(document.createTextNode(`showing the latest ${shown} of ${total} kept (${kept})`));
	if (total <= shown && !showAll[which]) return;
	el.appendChild(document.createTextNode(' '));
	const a = document.createElement('a');
	a.href = '#';
	a.textContent = showAll[which] ? 'show less' : 'show all';
	a.onclick = (e) => {
		e.preventDefault();
		showAll[which] = !showAll[which];
		const again = which === 'reports' ? loadReports() : loadEvents($('#ip').value.trim());
		again.catch((err) => show($('#err'), err.message, true));
	};
	el.appendChild(a);
}

async function loadReports() {
	const d = await api('/admin/reports?limit=' + pageLimit('reports'));
	// A paste expires sooner than a report, so the window is a ceiling rather than one number.
	moreLine($('#reportsNote'), 'reports', d.count, d.total, `up to ${d.retention_days} days`);
	const tb = $('#reports tbody');
	tb.replaceChildren();
	if (!d.reports.length) {
		const tr = document.createElement('tr');
		const td = cell(tr, 'nothing stored');
		td.className = 'muted';
		td.colSpan = 6;
		tb.appendChild(tr);
		return;
	}
	for (const r of d.reports) {
		const tr = document.createElement('tr');
		codeLink(cell(tr, ''), r.slug, API + '/' + r.slug, { blank: true });
		cell(tr, r.kind || '?');
		cell(tr, fmtBytes(r.size), true);
		cell(tr, stamp(r.at));
		cell(tr, stamp(r.expires));
		// A link, not a button: same action, and it is what keeps the row the height of the
		// builder's rows rather than a button's.
		const td = document.createElement('td');
		const act = document.createElement('a');
		act.href = '#';
		act.className = 'text-secondary small ms-1';
		act.textContent = 'remove';
		act.title = 'delete this report';
		act.onclick = async (e) => {
			e.preventDefault();
			if (!(await askConfirm(act, `Delete ${r.slug}? The submission record is kept.`, 'Delete'))) return;
			const res = await fetch(API + '/' + r.slug, {
				method: 'DELETE',
				headers: { authorization: 'Bearer ' + key },
			});
			if (res.ok) {
				tr.remove();
				loadStats();
			} else {
				$('#purgeNote').textContent = `delete failed: HTTP ${res.status}`;
			}
		};
		td.appendChild(act);
		tr.appendChild(td);
		tb.appendChild(tr);
	}
}

async function loadEvents(ip) {
	const limit = pageLimit('events');
	const d = await api('/admin/events' + (ip ? '?ip=' + encodeURIComponent(ip) + '&limit=' + limit : '?limit=' + limit));
	moreLine($('#eventsNote'), 'events', d.count, d.total, `${d.retention_days} days`);
	const tb = $('#events tbody');
	tb.replaceChildren();
	if (!d.events.length) {
		const tr = document.createElement('tr');
		const td = cell(tr, 'nothing logged');
		td.className = 'muted';
		td.colSpan = 7;
		tb.appendChild(tr);
		return;
	}
	// Column order follows the builder's recent events: when, what, which one, who.
	for (const r of d.events) {
		const tr = document.createElement('tr');
		cell(tr, stamp(r.at));
		cell(tr, r.kind);
		// Only a submission carries a slug, and only while the report is still there, so the
		// rest of the row types leave these cells empty rather than showing a placeholder.
		if (r.slug) cell(tr, r.slug, true);
		else cell(tr, '');
		cell(tr, r.admin || '');
		const td = cell(tr, '');
		if (r.ip) {
			if (r.country) {
				const g = document.createElement('span');
				g.className = 'me-1';
				g.title = r.country;
				g.textContent = flag(r.country);
				td.appendChild(g);
			}
			codeLink(td, r.ip, null, { ipc: true }).onclick = (e) => {
				e.preventDefault();
				$('#ip').value = r.ip;
				loadEvents(r.ip);
			};
		}
		cell(tr, r.detail || '').className = 'muted';
		cell(tr, stamp(r.record_expires));
		tb.appendChild(tr);
	}
}

// Bounded per call by the Worker, which reports what is left rather than pretending to
// finish, so this loops until it is done instead of leaving a half-purged table behind.
async function purge(what, label, count) {
	// Plain textContent, not show(): that helper rewrites className into an alert box, which
	// would turn this muted span into a coloured banner.
	if (!count) {
		$('#purgeNote').textContent = `no ${label} to delete`;
		return;
	}
	if (!confirm(`Delete all ${count} ${label}? This cannot be undone.`)) return;

	const btns = [$('#purgeReports'), $('#purgeEvents')];
	btns.forEach((b) => (b.disabled = true));
	let total = 0;
	try {
		for (let pass = 0; pass < 50; pass++) {
			const r = await fetch(`${API}/admin/${what}?confirm=all`, {
				method: 'DELETE',
				headers: { authorization: 'Bearer ' + key },
			});
			if (!r.ok) throw new Error('HTTP ' + r.status);
			const d = await r.json();
			total += d.deleted;
			$('#purgeNote').textContent = `deleted ${total}, ${d.remaining} left...`;
			if (!d.remaining || !d.deleted) break;
		}
		$('#purgeNote').textContent = `deleted ${total} ${label}`;
	} catch (e) {
		$('#purgeNote').textContent = 'failed: ' + e.message;
	}
	btns.forEach((b) => (b.disabled = false));
	refresh();
}

async function refresh() {
	closeConfirm(false);
	show($('#err'), '');
	try {
		await Promise.all([loadStats(), loadTtl(), loadReports(), loadEvents($('#ip').value.trim())]);
		$('#updated').textContent = 'updated ' + new Date().toLocaleTimeString([], HMS);
	} catch (e) {
		show($('#err'), e.message, true);
	}
}

function enter(tok) {
	key = tok;
	sessionStorage.setItem(KEY, tok);
	$('#gate').style.display = 'none';
	$('#app').style.display = '';
	refresh();
}

// In token mode the credential is the bin's own; in builder mode it goes to the builder
// and never touches the bin.
async function signin() {
	const e = $('#gateErr');
	show(e, 'signing in...');

	// Which mode this is decides where the credential goes, so it has to be settled
	// before branching. AUTH_MODE starts at 'builder' and is filled in by an async fetch,
	// so submitting inside that window used to take the builder path and POST a token
	// deployment's ADMIN_KEY to AUTH_ORIGIN as a password.
	await modeReady;

	if (AUTH_MODE === 'token') {
		const candidate = $('#p').value.trim();
		if (!candidate) return show(e, 'enter the admin key', true);
		// Nothing to exchange: the key is the credential. Probe one endpoint so a wrong
		// key is reported here rather than as a broken-looking page.
		const r = await fetch(API + '/admin/stats', { headers: { authorization: 'Bearer ' + candidate } });
		if (!r.ok) return show(e, 'rejected: check the admin key', true);
		show(e, '');
		$('#p').value = '';
		return enter(candidate);
	}

	if (!AUTH) {
		show(e, 'AUTH_ORIGIN is not configured in config.js', true);
		return;
	}
	// Master token and username/password are two bodies for the same builder endpoint, which is
	// how the builder itself does it. Either way the 6-digit code is sent: the master token is a
	// credential, not a bypass.
	// `app` is an audit label so the builder can record which door this login came through, and
	// so this page can show only its own. Not a credential and not a permission: the builder
	// prefers the Origin header and falls back to this only for a caller that sends none.
	const body = masterMode
		? { token: $('#mt').value.trim(), totp: $('#t').value.trim(), app: 'tb' }
		: {
				username: $('#u').value.trim().toLowerCase(),
				password: $('#p').value,
				totp: $('#t').value.trim(),
				app: 'tb',
			};
	let r, d;
	try {
		r = await fetch(AUTH + '/api/admin/login', {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify(body),
		});
		d = await r.json();
	} catch (err) {
		show(e, 'could not reach the builder: ' + err.message, true);
		return;
	}
	if (!r.ok || !d.session) {
		show(e, d && d.error ? d.error : 'HTTP ' + r.status, true);
		return;
	}
	show(e, '');
	$('#p').value = '';
	$('#mt').value = '';
	$('#t').value = '';
	enter(d.session);
}

// Revoking is the builder's job, so ask it directly. The bin never writes to the
// builder's database.
//
// Only in builder mode, and the check is not cosmetic. In token mode `key` is this
// deployment's own ADMIN_KEY and AUTH_ORIGIN is whatever config.js happens to say, which
// for anyone self-hosting from the committed default is thingino's image builder. Without
// the mode test, signing out handed the admin key to an unrelated origin.
async function lock() {
	await modeReady;
	if (key && AUTH && AUTH_MODE === 'builder') {
		try {
			await fetch(AUTH + '/api/admin/logout', {
				method: 'POST',
				headers: { authorization: 'Bearer ' + key },
			});
		} catch (_) {
			/* signing out locally regardless */
		}
	}
	sessionStorage.removeItem(KEY);
	location.reload();
}

// Which credential the gate asks for depends on the deployment. /admin/mode is public
// and says only which mode is in use, so a static file can adapt without config.js and
// the Worker staying in sync by hand.
async function applyAuthMode() {
	let mode = 'builder';
	try {
		const r = await fetch(API + '/admin/mode');
		if (r.ok) mode = (await r.json()).auth_mode || mode;
	} catch (_) {
		/* leave the default; signing in will report the real problem */
	}

	if (mode === 'none') {
		$('#gate').innerHTML = '';
		const card = document.createElement('div');
		card.className = 'card';
		const body = document.createElement('div');
		body.className = 'card-body';
		const h = document.createElement('h2');
		h.className = 'card-title fs-5 mb-2';
		h.textContent = 'Admin disabled';
		const p = document.createElement('p');
		p.className = 'small muted mb-0';
		p.textContent =
			'This deployment runs with no admin. Reports still expire on their own, and ' +
			'whoever uploaded one can delete it with the token they were given.';
		body.append(h, p);
		card.appendChild(body);
		$('#gate').appendChild(card);
		return mode;
	}

	if (mode === 'token') {
		// One shared secret, so username and TOTP are meaningless here. Hiding the inputs
		// directly rather than wrapping them: a lone input inside a Bootstrap .row picks up
		// the grid's negative margins and renders wider than its siblings.
		$('#u').hidden = true;
		$('#t').hidden = true;
		$('#p').placeholder = 'admin key';
		$('#p').autocomplete = 'current-password';
		$('#gateHint').textContent =
			'Sign in with this deployment\u2019s admin key. It is kept in this tab only, never in a cookie.';
		$('#masterToggle').hidden = true;
	}
	return mode;
}

// Which credential the builder gate is asking for. The old alternative here was pasting a
// raw session token straight into storage, which is not a credential at all: it only worked if
// you already had a session from somewhere else, and it skipped the second factor entirely.
let masterMode = false;

function setMaster(on) {
	masterMode = on;
	$('#u').hidden = on;
	$('#p').hidden = on;
	$('#mt').hidden = !on;
	$('#masterToggle').textContent = on ? 'Use username and password instead' : 'Use master token instead';
	$('#gateHint').textContent = on
		? 'Sign in with the builder\u2019s master token and its 6-digit code. The session is issued by the builder and kept in this tab only, never in a cookie.'
		: 'Sign in with your thingino builder account. The session is issued by the builder and kept in this tab only, never in a cookie.';
	(on ? $('#mt') : $('#u')).focus();
}

let AUTH_MODE = 'builder';
// Awaited by anything that acts on the mode, so a fast click cannot race the fetch.
let modeReady = Promise.resolve();

window.addEventListener('DOMContentLoaded', () => {
	// v<version>-<short sha>, per the shared footer convention. The sha is written into
	// config.js by the Pages workflow, the same way the builder injects API_BASE.
	$('#version-num').textContent = 'v' + (window.APP_VERSION || '0.0.0') + '-' + (window.GIT_SHA || 'dev');

	// Real forms: browsers warn about password fields outside one, password managers
	// will not offer to fill or save, and Enter-to-submit comes for free.
	$('#loginForm').addEventListener('submit', (e) => {
		e.preventDefault();
		signin();
	});
	$('#masterToggle').onclick = (e) => {
		e.preventDefault();
		setMaster(!masterMode);
	};
	$('#refresh').onclick = refresh;
	$('#kill-btn').onclick = toggleKill;
	$('#saveTtl').onclick = saveTtl;
	$('#purgeReports').onclick = () => purge('reports', 'reports', lastCounts.reports);
	$('#purgeEvents').onclick = () => purge('events', 'log entries', lastCounts.events);
	$('#findForm').addEventListener('submit', (e) => {
		e.preventDefault();
		loadEvents($('#ip').value.trim());
	});
	$('#lock').onclick = lock;

	modeReady = applyAuthMode().then((m) => {
		AUTH_MODE = m;
	});

	if (key) {
		$('#gate').style.display = 'none';
		$('#app').style.display = '';
		refresh();
	}
});

// Refresh on a timer, which is also what keeps the session alive. The Worker slides the builder's
// idle window on any authenticated request, but only on a request: a portal that never polls makes
// none, so `last_active` stayed at login time and the session died at the 2 hour idle mark while
// the 8 hour cap was still hours away. The builder's own panel polls, which is why it never showed
// this. Skipped while the tab is hidden or a confirm popover is open, so a background tab does not
// spend reads and a redraw does not yank a popover off its anchor.
const POLL_MS = 60000;
setInterval(() => {
	if (document.hidden || cpop) return;
	if ($('#app').style.display !== 'none' && key) refresh();
}, POLL_MS);
document.addEventListener('visibilitychange', () => {
	if (!document.hidden && $('#app').style.display !== 'none' && key) refresh();
});
