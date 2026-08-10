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

const ago = (iso) => {
	const s = (Date.now() - new Date(iso)) / 1000;
	if (s < 90) return Math.round(s) + 's ago';
	if (s < 5400) return Math.round(s / 60) + 'm ago';
	if (s < 172800) return Math.round(s / 3600) + 'h ago';
	return Math.round(s / 86400) + 'd ago';
};

const until = (iso) => {
	const s = (new Date(iso) - Date.now()) / 1000;
	if (s < 0) return 'expired';
	if (s < 5400) return 'in ' + Math.round(s / 60) + 'm';
	if (s < 172800) return 'in ' + Math.round(s / 3600) + 'h';
	return 'in ' + Math.round(s / 86400) + 'd';
};

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
const lastCounts = { reports: 0, abuse: 0 };

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

async function loadStats() {
	const s = await api('/admin/stats');
	lastCounts.reports = s.reports.total;
	lastCounts.abuse = s.abuse.records;
	renderKill(Boolean(s.budget.paused));
	const c = $('#stats');
	c.replaceChildren(
		statCard(s.reports.total, 'reports stored'),
		statCard(fmtBytes(s.reports.bytes), 'report bytes'),
		statCard(fmtBytes(s.database.bytes), 'database size'),
		statCard(s.database.percent_of_limit + '%', 'of 500 MiB'),
		statCard(s.abuse.records, 'abuse records'),
	);
	const b = $('#budget');
	b.replaceChildren();
	const k = s.budget.kinds || {};
	for (const name of ['diag', 'paste']) {
		const v = k[name] || { n: 0, bytes: 0 };
		b.append(statCard(v.n + ' / ' + fmtBytes(v.bytes), name + ' today'));
	}
}

async function loadReports() {
	const d = await api('/admin/reports?limit=100');
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
		cell(tr, ago(r.at));
		cell(tr, until(r.expires));
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

async function loadAbuse(ip) {
	const q = ip ? '?ip=' + encodeURIComponent(ip) + '&limit=200' : '?limit=100';
	const d = await api('/admin/abuse' + q);
	$('#abuseNote').textContent = 'kept ' + d.retention_days + ' days, ' + d.count + ' shown';
	const tb = $('#abuse tbody');
	tb.replaceChildren();
	if (!d.submissions.length) {
		const tr = document.createElement('tr');
		const td = cell(tr, 'no records');
		td.className = 'muted';
		td.colSpan = 5;
		tb.appendChild(tr);
		return;
	}
	for (const r of d.submissions) {
		const tr = document.createElement('tr');
		const td = cell(tr, '');
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
			loadAbuse(r.ip);
		};
		cell(tr, r.slug, true);
		cell(tr, r.kind || '?');
		cell(tr, ago(r.at));
		cell(tr, until(r.record_expires));
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

	const btns = [$('#purgeReports'), $('#purgeAbuse')];
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
		await Promise.all([loadStats(), loadReports(), loadAbuse($('#ip').value.trim())]);
		$('#updated').textContent = 'updated ' + new Date().toLocaleTimeString();
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
	const body = masterMode
		? { token: $('#mt').value.trim(), totp: $('#t').value.trim() }
		: {
				username: $('#u').value.trim().toLowerCase(),
				password: $('#p').value,
				totp: $('#t').value.trim(),
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
	$('#purgeReports').onclick = () => purge('reports', 'reports', lastCounts.reports);
	$('#purgeAbuse').onclick = () => purge('abuse', 'submission records', lastCounts.abuse);
	$('#findForm').addEventListener('submit', (e) => {
		e.preventDefault();
		loadAbuse($('#ip').value.trim());
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
